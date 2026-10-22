//
//  GSAClient.swift
//  GhostSign
//
//  HTTP Client for Apple's GrandSlam Authentication Service (GsService2).
//

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public struct GSAInitResponse: Sendable {
    public let challenge: String
    public let salt: Data
    public let iterations: Int
    public let serverPublicKeyB: Data
    public let isS2KFO: Bool
}

public struct GSACompleteResponse: @unchecked Sendable {
    public let serverProofM2: Data
    public let encryptedSPD: Data
    public let requires2FA: Bool
    public let authType: String?
    public let statusDictionary: [String: Any]
}

public final class GSAClient: Sendable {
    public enum Endpoints {
        public static let grandSlamAuth = URL(string: "https://gsa.apple.com/grandslam/GsService2")!
        public static let grandSlamValidate = URL(string: "https://gsa.apple.com/grandslam/GsService2/validate")!
        public static let trustedDevice = URL(string: "https://gsa.apple.com/auth/verify/trusteddevice")!
        public static let phoneSecurityCode = URL(string: "https://gsa.apple.com/auth/verify/phone/securitycode?referrer=/auth/verify/phone/put")!

        public static func phonePut(mode: String = "sms") -> URL {
            URL(string: "https://gsa.apple.com/auth/verify/phone/put?mode=\(mode)") ?? Endpoints.grandSlamAuth
        }
    }

    private let urlSession: URLSession

    public init(urlSession: URLSession = .shared) {
        self.urlSession = urlSession
    }

    /// Builds the standard GrandSlam client payload dictionary containing Anisette data.
    public func makeClientDictionary(anisette: AnisetteData) -> [String: Any] {
        [
            "bootstrap": true,
            "icscrec": true,
            "pbe": false,
            "prkgen": true,
            "svct": "iCloud",
            "loc": anisette.locale,
            "X-Apple-Locale": anisette.locale,
            "X-Apple-I-MD": anisette.oneTimePassword,
            "X-Apple-I-MD-M": anisette.machineID,
            "X-Mme-Device-Id": anisette.deviceID,
            "X-Apple-I-MD-LU": anisette.localUserID,
            "X-Apple-I-MD-RINFO": anisette.routingInfo,
            "X-Apple-I-SRL-NO": anisette.serialNumber,
            "X-Apple-I-Client-Time": anisette.clientTime,
            "X-Apple-I-TimeZone": anisette.timeZone
        ]
    }

    /// Sends a POST request to GsService2 wrapping the payload in Header/Request XML plist.
    public func sendGrandSlamRequest(
        parameters: [String: Any],
        anisette: AnisetteData,
        targetURL: URL = Endpoints.grandSlamAuth,
        additionalHeaders: [String: String] = [:]
    ) async throws -> [String: Any] {
        let envelope: [String: Any] = [
            "Header": ["Version": "1.0.1"],
            "Request": parameters
        ]

        let plistData = try PropertyListSerialization.data(fromPropertyList: envelope, format: .xml, options: 0)

        var request = URLRequest(url: targetURL)
        request.httpMethod = "POST"
        request.httpBody = plistData

        request.setValue("text/x-xml-plist", forHTTPHeaderField: "Content-Type")
        request.setValue("*/*", forHTTPHeaderField: "Accept")
        request.setValue(anisette.userAgent, forHTTPHeaderField: "User-Agent")
        request.setValue(anisette.clientInfo, forHTTPHeaderField: Constants.AnisetteHeaders.mmeClientInfo)
        request.setValue(anisette.clientInfo, forHTTPHeaderField: Constants.AnisetteHeaders.appleClientInfo)
        request.setValue("close", forHTTPHeaderField: "Connection")

        for (header, value) in additionalHeaders {
            request.setValue(value, forHTTPHeaderField: header)
        }

        let (data, response) = try await urlSession.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw AppleAuthError.badServerResponse("No HTTP response received from GrandSlam.")
        }

        guard !data.isEmpty else {
            throw AppleAuthError.badServerResponse("Empty response (HTTP \(httpResponse.statusCode)).")
        }

        guard let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] else {
            let str = String(data: data, encoding: .utf8) ?? "binary data"
            throw AppleAuthError.badServerResponse("Invalid XML plist from GrandSlam: \(str)")
        }

        let responseDict = (plist["Response"] as? [String: Any]) ?? plist

        if let status = responseDict["Status"] as? [String: Any] {
            let errorCode = status["ec"] as? Int ?? 0
            if errorCode != 0 {
                let errorMsg = status["em"] as? String ?? "GrandSlam Error (\(errorCode))"
                if errorCode == -22406 {
                    throw AppleAuthError.invalidCredentials(errorMsg)
                } else if errorCode == -21669 {
                    throw AppleAuthError.invalid2FACode(errorMsg)
                } else {
                    throw AppleAuthError.badServerResponse(errorMsg)
                }
            }
        }

        return responseDict
    }

    /// Step 1: Initiates SRP authentication by sending client public key A.
    public func sendInit(
        appleID: String,
        clientPublicKeyA: Data,
        anisette: AnisetteData
    ) async throws -> GSAInitResponse {
        let params: [String: Any] = [
            "A2k": clientPublicKeyA,
            "cpd": makeClientDictionary(anisette: anisette),
            "o": "init",
            "ps": ["s2k", "s2k_fo"],
            "u": appleID
        ]

        let response = try await sendGrandSlamRequest(parameters: params, anisette: anisette)

        guard let c = response["c"] as? String,
              let salt = response["s"] as? Data,
              let iterations = response["i"] as? Int,
              let b = response["B"] as? Data
        else {
            throw AppleAuthError.badServerResponse("Missing required parameters (c/s/i/B) in GSA init response.")
        }

        let sp = response["sp"] as? String
        let isS2KFO = (sp == "s2k_fo")

        return GSAInitResponse(
            challenge: c,
            salt: salt,
            iterations: iterations,
            serverPublicKeyB: b,
            isS2KFO: isS2KFO
        )
    }

    /// Step 2: Completes SRP authentication by sending client verification proof M1.
    public func sendComplete(
        appleID: String,
        proofM1: Data,
        challenge: String,
        anisette: AnisetteData
    ) async throws -> GSACompleteResponse {
        let params: [String: Any] = [
            "c": challenge,
            "cpd": makeClientDictionary(anisette: anisette),
            "M1": proofM1,
            "o": "complete",
            "u": appleID
        ]

        let response = try await sendGrandSlamRequest(parameters: params, anisette: anisette)

        guard let m2 = response["M2"] as? Data else {
            throw AppleAuthError.badServerResponse("Missing server verification proof M2 in complete response.")
        }

        guard let spd = response["spd"] as? Data else {
            throw AppleAuthError.badServerResponse("Missing encrypted SPD payload in complete response.")
        }

        let status = (response["Status"] as? [String: Any]) ?? [:]
        let authType = (status["au"] as? String) ?? (response["au"] as? String)

        let is2FARequired: Bool
        if let type = authType {
            is2FARequired = ["trustedDeviceSecondaryAuth", "trustedDevice", "secondaryAuth", "sms", "voice", "phone", "pushedCode"].contains(type)
        } else {
            is2FARequired = (status["hsc"] as? Int == 409)
        }

        return GSACompleteResponse(
            serverProofM2: m2,
            encryptedSPD: spd,
            requires2FA: is2FARequired,
            authType: authType,
            statusDictionary: status
        )
    }

    /// Step 3: Fetches the Xcode Bearer token (com.apple.gs.xcode.auth) using the decrypted session key.
    public func sendAppTokens(
        dsid: String,
        idmsToken: String,
        sessionKey: Data,
        challengeToken: Data?,
        anisette: AnisetteData,
        targetApp: String = "com.apple.gs.xcode.auth"
    ) async throws -> (token: String, expirationDate: Date?) {
        guard let checksum = CryptoUtilities.hmacSHA256(key: sessionKey, strings: ["apptokens", dsid, targetApp]) else {
            throw AppleAuthError.handshakeFailed("Failed to compute apptokens checksum.")
        }

        var params: [String: Any] = [
            "app": [targetApp],
            "checksum": checksum,
            "cpd": makeClientDictionary(anisette: anisette),
            "o": "apptokens",
            "t": idmsToken,
            "u": dsid
        ]

        if let c = challengeToken {
            params["c"] = c
        }

        let response = try await sendGrandSlamRequest(parameters: params, anisette: anisette)

        guard let encryptedToken = response["et"] as? Data else {
            throw AppleAuthError.badServerResponse("Missing encrypted token 'et' in apptokens response.")
        }

        return try SRPClient.decryptAppToken(encryptedToken: encryptedToken, sessionKey: sessionKey, targetApp: targetApp)
    }

    /// Validates 6-digit 2FA OTP code against /grandslam/GsService2/validate.
    public func validate2FACode(
        code: String,
        dsid: String,
        idmsToken: String,
        anisette: AnisetteData
    ) async throws {
        let identityToken = "\(dsid):\(idmsToken)"
        let encodedIdentity = Data(identityToken.utf8).base64EncodedString()

        var request = URLRequest(url: Endpoints.grandSlamValidate)
        request.httpMethod = "POST"
        request.setValue("text/x-xml-plist", forHTTPHeaderField: "Content-Type")
        request.setValue("*/*", forHTTPHeaderField: "Accept")
        request.setValue(anisette.userAgent, forHTTPHeaderField: "User-Agent")
        request.setValue(anisette.clientInfo, forHTTPHeaderField: Constants.AnisetteHeaders.mmeClientInfo)
        request.setValue(anisette.clientInfo, forHTTPHeaderField: Constants.AnisetteHeaders.appleClientInfo)
        request.setValue(encodedIdentity, forHTTPHeaderField: "X-Apple-Identity-Token")
        request.setValue("com.apple.gs.xcode.auth", forHTTPHeaderField: "X-Apple-App-Info")
        request.setValue("15.4 (15F31d)", forHTTPHeaderField: "X-Xcode-Version")
        request.setValue(code, forHTTPHeaderField: "security-code")
        request.setValue(anisette.oneTimePassword, forHTTPHeaderField: "X-Apple-I-MD")
        request.setValue(anisette.machineID, forHTTPHeaderField: "X-Apple-I-MD-M")
        request.setValue(anisette.localUserID, forHTTPHeaderField: "X-Apple-I-MD-LU")
        request.setValue(anisette.routingInfo, forHTTPHeaderField: "X-Apple-I-MD-RINFO")

        let (data, response) = try await urlSession.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw AppleAuthError.badServerResponse("No HTTP response during 2FA validation.")
        }

        guard (200...299).contains(httpResponse.statusCode) else {
            let desc = String(data: data, encoding: .utf8) ?? "HTTP \(httpResponse.statusCode)"
            throw AppleAuthError.invalid2FACode(desc)
        }
    }
}
