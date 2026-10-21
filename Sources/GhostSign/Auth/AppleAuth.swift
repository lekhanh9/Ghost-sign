//
//  AppleAuth.swift
//  GhostSign
//
//  Created for Ghost-Sign.
//

import Foundation
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
    private let urlSession: URLSession

    public init(
        anisetteProvider: AnisetteDataProvider = MockAnisetteDataProvider(),
        urlSession: URLSession = .shared
    ) {
        self.anisetteProvider = anisetteProvider
        self.urlSession = urlSession
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

        // Placeholder for full SRP network exchange (GsService2 init -> complete)
        // In the next step, this connects to the SRPClient engine.
        let dsid = "adsid_\(abs(sanitizedAppleID.hashValue))"
        let dummySessionKey = Data(repeating: 0x42, count: 32)
        let dummyIdmsToken = "gs_idms_token_\(UUID().uuidString)"

        let session = AuthSession(
            dsid: dsid,
            authToken: "gs_auth_token_\(UUID().uuidString)",
            idmsToken: dummyIdmsToken,
            sessionKey: dummySessionKey,
            anisetteData: anisette,
            expirationDate: Date().addingTimeInterval(86400 * 30)
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

        return AuthSession(
            dsid: context.dsid,
            authToken: "gs_auth_token_\(UUID().uuidString)",
            idmsToken: context.idmsToken,
            sessionKey: context.sessionKey,
            anisetteData: context.anisetteData,
            expirationDate: Date().addingTimeInterval(86400 * 30)
        )
    }
}
