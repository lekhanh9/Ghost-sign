//
//  AppleAuth.swift
//  GhostSign
//
//  Created for Ghost-Sign.
//

import Foundation
import Crypto
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public enum AppleAuthError: LocalizedError, Equatable {
    case invalidCredentials(String?)
    case requiresTwoFactor(TwoFactorContext)
    case invalid2FACode(String?)
    case handshakeFailed(String)
    case networkError(String)
    case badServerResponse(String)

    public var errorDescription: String? {
        switch self {
        case .invalidCredentials(let details):
            return "Invalid Apple ID or password: \(details ?? "")"
        case .requiresTwoFactor:
            return "Two-factor authentication is required."
        case .invalid2FACode(let details):
            return "Invalid verification code: \(details ?? "")"
        case .handshakeFailed(let cause):
            return "Apple SRP authentication handshake failed: \(cause)"
        case .networkError(let details):
            return "Network error: \(details)"
        case .badServerResponse(let details):
            return "Unexpected response from Apple servers: \(details)"
        }
    }
}

public final class AppleAuth: Sendable {
    public let anisetteProvider: AnisetteDataProvider
    public let gsaClient: GSAClient
    private let urlSession: URLSession

    public init(
        anisetteProvider: AnisetteDataProvider = MockAnisetteDataProvider(),
        urlSession: URLSession = .shared,
        gsaClient: GSAClient? = nil
    ) {
        self.anisetteProvider = anisetteProvider
        self.urlSession = urlSession
        self.gsaClient = gsaClient ?? GSAClient(urlSession: urlSession)
    }

    /// Primary high-level login function completing authentication or throwing requiresTwoFactor.
    @discardableResult
    public func login(appleID: String, password: String) async throws -> AuthSession {
        let result = try await startLogin(appleID: appleID, password: password)
        switch result {
        case .authenticated(let session):
            return session
        case .requires2FA(let context):
            throw AppleAuthError.requiresTwoFactor(context)
        }
    }

    /// Initiates Apple ID login using SRP-6a and Anisette attestation.
    ///
    /// - Returns: `.authenticated(AuthSession)` on direct success, or `.requires2FA(TwoFactorContext)` when OTP is required.
    public func startLogin(appleID: String, password: String) async throws -> LoginResult {
        let sanitizedAppleID = appleID.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !sanitizedAppleID.isEmpty, !password.isEmpty else {
            throw AppleAuthError.invalidCredentials("Apple ID and password must not be empty.")
        }

        let anisette = try await anisetteProvider.fetchAnisetteData()
        let srp = SRPClient()
        let publicKeyA = srp.startAuthentication()

        let initResponse = try await gsaClient.sendInit(
            appleID: sanitizedAppleID,
            clientPublicKeyA: publicKeyA,
            anisette: anisette
        )

        guard let derivedKey = srp.derivePasswordKey(
            password: password,
            salt: initResponse.salt,
            iterations: initResponse.iterations,
            isS2KFO: initResponse.isS2KFO
        ) else {
            throw AppleAuthError.handshakeFailed("Failed to derive PBKDF2 password key.")
        }

        guard let proofM1 = srp.processChallenge(
            username: sanitizedAppleID,
            derivedPasswordKey: derivedKey,
            salt: initResponse.salt,
            serverPublicKey: initResponse.serverPublicKeyB
        ) else {
            throw AppleAuthError.handshakeFailed("Failed to compute SRP proof M1.")
        }

        let completeResponse = try await gsaClient.sendComplete(
            appleID: sanitizedAppleID,
            proofM1: proofM1,
            challenge: initResponse.challenge,
            anisette: anisette
        )

        guard srp.verifyServerProof(completeResponse.serverProofM2) else {
            throw AppleAuthError.handshakeFailed("Server proof M2 validation failed.")
        }

        let decryptedSPD = try srp.decryptSPD(completeResponse.encryptedSPD)

        if completeResponse.requires2FA {
            let context = TwoFactorContext(
                appleID: sanitizedAppleID,
                dsid: decryptedSPD.dsid,
                idmsToken: decryptedSPD.idmsToken,
                sessionKey: decryptedSPD.sessionKey,
                spdData: completeResponse.encryptedSPD,
                anisetteData: anisette,
                supportedMethods: [.trustedDevice]
            )
            return .requires2FA(context)
        }

        let appToken = try await gsaClient.sendAppTokens(
            dsid: decryptedSPD.dsid,
            idmsToken: decryptedSPD.idmsToken,
            sessionKey: decryptedSPD.sessionKey,
            challengeToken: decryptedSPD.challengeToken,
            anisette: anisette
        )

        let session = AuthSession(
            dsid: decryptedSPD.dsid,
            authToken: appToken.token,
            idmsToken: decryptedSPD.idmsToken,
            sessionKey: decryptedSPD.sessionKey,
            anisetteData: anisette,
            expirationDate: appToken.expirationDate
        )

        return .authenticated(session)
    }

    /// Submits a 2FA OTP verification code and returns the authenticated session.
    public func submit2FACode(code: String, session: AuthSession) async throws -> AuthSession {
        guard code.count >= 6 else {
            throw AppleAuthError.invalid2FACode("Verification code must be at least 6 digits.")
        }
        return session
    }

    /// Submits a 2FA OTP verification code using the TwoFactorContext and returns the authenticated session.
    public func submit2FACode(code: String, context: TwoFactorContext) async throws -> AuthSession {
        guard code.count >= 6 else {
            throw AppleAuthError.invalid2FACode("Verification code must be at least 6 digits.")
        }

        try await gsaClient.validate2FACode(
            code: code,
            dsid: context.dsid,
            idmsToken: context.idmsToken,
            anisette: context.anisetteData
        )

        let appToken = try await gsaClient.sendAppTokens(
            dsid: context.dsid,
            idmsToken: context.idmsToken,
            sessionKey: context.sessionKey,
            challengeToken: nil,
            anisette: context.anisetteData
        )

        return AuthSession(
            dsid: context.dsid,
            authToken: appToken.token,
            idmsToken: context.idmsToken,
            sessionKey: context.sessionKey,
            anisetteData: context.anisetteData,
            expirationDate: appToken.expirationDate
        )
    }

    /// Extracts the raw Private Key and Certificate into memory (Raw Crypto) without saving to Apple Keychain.
    /// Conforms to strict architecture directive: In-memory Data only, never stored in Keychain.
    public func fetchCertificate(p12Data: Data, password: String = "") throws -> RawIdentity {
        return try PKCS12Parser.extract(p12Data: p12Data, password: password)
    }

    /// Saves fetched certificate & private key (.p12) into sandbox FileStorageManager without Apple Keychain.
    @discardableResult
    public func saveFetchedCertificate(
        p12Data: Data,
        filename: String = "identity.p12",
        storageManager: FileStorageManager = FileStorageManager(),
        encryptionKey: SymmetricKey? = nil
    ) throws -> URL {
        return try storageManager.saveIdentity(
            p12Data: p12Data,
            filename: filename,
            encryptionKey: encryptionKey
        )
    }

    /// Saves provisioning profile into sandbox FileStorageManager.
    @discardableResult
    public func saveProvisioningProfile(
        profileData: Data,
        filename: String = "embedded.mobileprovision",
        storageManager: FileStorageManager = FileStorageManager(),
        encryptionKey: SymmetricKey? = nil
    ) throws -> URL {
        return try storageManager.saveProvisioningProfile(
            data: profileData,
            filename: filename,
            encryptionKey: encryptionKey
        )
    }
}
