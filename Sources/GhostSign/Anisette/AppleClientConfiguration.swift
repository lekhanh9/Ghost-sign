//
//  AppleClientConfiguration.swift
//  GhostSign
//
//  User-configurable identification sent to Apple services.
//

import Foundation

/// Spoofed client identity applied to GrandSlam and Developer Services requests.
public struct AppleClientConfiguration: Sendable, Equatable {
    public static let defaultUserAgent = GhostSignConstants.GrandSlam.userAgent
    public static let defaultClientInfo =
        "<MacBookPro18,1> <macOS;14.5;23F79> <com.apple.AuthKit/1 (com.apple.dt.Xcode/15.4)>"

    public static let `default` = AppleClientConfiguration()

    public let userAgent: String
    public let clientInfo: String

    public init(userAgent: String? = nil, clientInfo: String? = nil) {
        self.userAgent = Self.sanitized(userAgent, fallback: Self.defaultUserAgent)
        self.clientInfo = Self.sanitized(clientInfo, fallback: Self.defaultClientInfo)
    }

    /// Returns a copy of the anisette data carrying this client identity.
    public func applying(to anisette: AnisetteData) -> AnisetteData {
        var configured = anisette
        configured.userAgent = userAgent
        configured.clientInfo = clientInfo
        return configured
    }

    /// Header values must stay single-line: strip control characters so a custom
    /// value cannot inject extra headers.
    private static func sanitized(_ value: String?, fallback: String) -> String {
        guard let value else { return fallback }
        let cleaned = value
            .components(separatedBy: .controlCharacters)
            .joined()
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return cleaned.isEmpty ? fallback : cleaned
    }
}
