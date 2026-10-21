//
//  AuthSession.swift
//  GhostSign
//
//  Created for Ghost-Sign.
//

import Foundation

/// Represents an authenticated Apple ID session capable of making Developer Portal requests.
public struct AuthSession: Sendable, Codable, Equatable {
    /// Apple Directory Service ID (DSID / Account ID).
    public var dsid: String

    /// The Xcode developer services bearer token (com.apple.gs.xcode.auth).
    public var authToken: String

    /// GrandSlam IDMS session token.
    public var idmsToken: String

    /// Master session key derived during the SRP handshake.
    public var sessionKey: Data

    /// The Anisette data snapshot used for this session.
    public var anisetteData: AnisetteData

    /// Creation timestamp of the session.
    public var creationDate: Date

    /// Expiration timestamp of the authentication token.
    public var expirationDate: Date?

    /// Selected Apple Developer Team ID (if resolved).
    public var teamID: String?

    public var isExpired: Bool {
        guard let expirationDate else { return false }
        return Date() >= expirationDate
    }

    public var isValid: Bool {
        !isExpired
    }

    public init(
        dsid: String,
        authToken: String,
        idmsToken: String,
        sessionKey: Data,
        anisetteData: AnisetteData,
        creationDate: Date = Date(),
        expirationDate: Date? = nil,
        teamID: String? = nil
    ) {
        self.dsid = dsid
        self.authToken = authToken
        self.idmsToken = idmsToken
        self.sessionKey = sessionKey
        self.anisetteData = anisetteData
        self.creationDate = creationDate
        self.expirationDate = expirationDate
        self.teamID = teamID
    }
}

/// Represents the intermediate state when Apple ID login requires Two-Factor Authentication.
public struct TwoFactorContext: Sendable, Equatable {
    public enum DeliveryMethod: Sendable, Equatable {
        case trustedDevice
        case sms(phoneID: String, obfuscatedNumber: String)
        case voice(phoneID: String, obfuscatedNumber: String)
    }

    public let appleID: String
    public let dsid: String
    public let idmsToken: String
    public let sessionKey: Data
    public let spdData: Data
    public let anisetteData: AnisetteData
    public let supportedMethods: [DeliveryMethod]

    public init(
        appleID: String,
        dsid: String,
        idmsToken: String,
        sessionKey: Data,
        spdData: Data,
        anisetteData: AnisetteData,
        supportedMethods: [DeliveryMethod] = [.trustedDevice]
    ) {
        self.appleID = appleID
        self.dsid = dsid
        self.idmsToken = idmsToken
        self.sessionKey = sessionKey
        self.spdData = spdData
        self.anisetteData = anisetteData
        self.supportedMethods = supportedMethods
    }
}

/// Result returned from `startLogin`.
public enum LoginResult: Sendable, Equatable {
    case authenticated(AuthSession)
    case requires2FA(TwoFactorContext)
}
