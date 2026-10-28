//
//  DeveloperPortalError.swift
//  GhostSign
//
//  Created for Ghost-Sign.
//

import Foundation

/// Strongly-typed errors mapped from Apple Developer Services (QH65B2) responses.
public enum DeveloperPortalError: Error, CustomStringConvertible, LocalizedError, Sendable, Equatable {
    /// Generic or unmapped Developer Portal error with raw result code and message.
    case portalError(code: Int, message: String)

    /// A device with this UDID is already registered to the developer team (resultCode 35).
    case deviceAlreadyRegistered

    /// The team has reached the maximum number of registered test devices.
    case maximumDevicesReached

    /// The bundle identifier is already registered by another team or unavailable (resultCode 35).
    case bundleIdentifierUnavailable

    /// The account has reached the maximum number of registered App IDs (resultCode 37).
    case maximumAppIDLimitReached

    /// The Certificate Signing Request (CSR) was invalid, corrupt, or rejected (resultCode 3250).
    case invalidCertificateRequest

    /// The account has reached the maximum number of active development certificates (resultCode 35 / 7460).
    case maximumCertificatesReached

    /// The requested development certificate was not found on the portal.
    case certificateNotFound

    /// The requested provisioning profile or App ID was not found on the portal (resultCode 8201 / 9115).
    case profileNotFound

    /// The App ID was not found on the developer portal.
    case appIDNotFound

    /// The requested Application Group was not found or does not exist (resultCode 35).
    case appGroupDoesNotExist(String)

    /// The session token expired or authentication was rejected by Apple ID services.
    case unauthenticated(String)

    /// No developer teams are associated with the authenticated account.
    case noTeams

    /// The response from Apple Developer Services was corrupted or had an unexpected format.
    case invalidResponseFormat(String)

    /// Network communication error with Apple Developer Services.
    case networkError(any Error & Sendable)

    /// Response payload decoding error.
    case decodingError(any Error & Sendable)

    // MARK: - Compatibility Aliases

    /// Alias for maximumCertificatesReached (resultCode 35 / 7460).
    public static var tooManyCertificates: DeveloperPortalError {
        .maximumCertificatesReached
    }

    /// Alias for profileNotFound (resultCode 8201 / 9115).
    public static var appIDDoesNotExist: DeveloperPortalError {
        .profileNotFound
    }

    /// Convenience helper for string-based network errors.
    public static func networkError(_ message: String) -> DeveloperPortalError {
        .networkError(NSError(domain: "DeveloperPortalClient", code: -1, userInfo: [NSLocalizedDescriptionKey: message]))
    }

    /// Convenience helper for string-based decoding errors.
    public static func decodingError(_ message: String) -> DeveloperPortalError {
        .decodingError(NSError(domain: "DeveloperPortalClient", code: -1, userInfo: [NSLocalizedDescriptionKey: message]))
    }

    // MARK: - CustomStringConvertible & LocalizedError

    public var description: String {
        switch self {
        case .portalError(let code, let msg):
            return "Apple Developer Portal returned error (\(code)): \(msg)"
        case .deviceAlreadyRegistered:
            return "The device UDID is already registered to this developer team."
        case .maximumDevicesReached:
            return "The maximum number of registered devices has been reached for this team."
        case .bundleIdentifierUnavailable:
            return "The bundle identifier is unavailable or already registered."
        case .maximumAppIDLimitReached:
            return "The maximum App ID limit has been reached for this account (free accounts are limited to 10 active App IDs)."
        case .invalidCertificateRequest:
            return "The certificate signing request (CSR) is invalid, malformed, or rejected by Apple's CA."
        case .maximumCertificatesReached:
            return "The maximum number of active development certificates has been reached for this account."
        case .certificateNotFound:
            return "The requested development certificate was not found on the developer portal."
        case .profileNotFound:
            return "The requested provisioning profile was not found on the developer portal."
        case .appIDNotFound:
            return "The requested App ID was not found on the developer portal."
        case .appGroupDoesNotExist(let msg):
            return "The application group does not exist on the developer portal: \(msg)"
        case .unauthenticated(let msg):
            return "Apple Developer Services authentication failed: \(msg)"
        case .noTeams:
            return "No developer teams found for the authenticated Apple ID."
        case .invalidResponseFormat(let msg):
            return "Invalid response format from Apple Developer Services: \(msg)"
        case .networkError(let err):
            return "Network error occurred while communicating with Apple Developer Services: \(err.localizedDescription)"
        case .decodingError(let err):
            return "Failed to decode Apple Developer Portal response payload: \(err.localizedDescription)"
        }
    }

    public var errorDescription: String? {
        description
    }

    // MARK: - Equatable

    public static func == (lhs: DeveloperPortalError, rhs: DeveloperPortalError) -> Bool {
        switch (lhs, rhs) {
        case (.portalError(let c1, let m1), .portalError(let c2, let m2)):
            return c1 == c2 && m1 == m2
        case (.deviceAlreadyRegistered, .deviceAlreadyRegistered),
             (.maximumDevicesReached, .maximumDevicesReached),
             (.bundleIdentifierUnavailable, .bundleIdentifierUnavailable),
             (.maximumAppIDLimitReached, .maximumAppIDLimitReached),
             (.invalidCertificateRequest, .invalidCertificateRequest),
             (.maximumCertificatesReached, .maximumCertificatesReached),
             (.certificateNotFound, .certificateNotFound),
             (.profileNotFound, .profileNotFound),
             (.noTeams, .noTeams):
            return true
        case (.unauthenticated(let m1), .unauthenticated(let m2)):
            return m1 == m2
        case (.invalidResponseFormat(let m1), .invalidResponseFormat(let m2)):
            return m1 == m2
        case (.networkError(let e1), .networkError(let e2)):
            return e1.localizedDescription == e2.localizedDescription
        case (.decodingError(let e1), .decodingError(let e2)):
            return e1.localizedDescription == e2.localizedDescription
        default:
            return false
        }
    }
}

// MARK: - Result Code Mapper

/// Maps Apple QH65B2 result codes and error messages into strongly-typed `DeveloperPortalError` cases.
public struct DeveloperPortalResultCodeMapper {
    public static func map(code: Int, message: String, context: String? = nil) -> DeveloperPortalError {
        switch code {
        case Constants.ResultCodes.invalidCertificateRequest:
            return .invalidCertificateRequest
        case Constants.ResultCodes.maximumAppIDLimitReached:
            return .maximumAppIDLimitReached
        case Constants.ResultCodes.maximumCertificatesReachedAlternate:
            return .maximumCertificatesReached
        case Constants.ResultCodes.profileNotFound, Constants.ResultCodes.profileNotFoundAlternate:
            return .profileNotFound
        case Constants.ResultCodes.sessionExpired:
            return .unauthenticated(message)
        case Constants.ResultCodes.deviceAlreadyRegistered: // 35
            let lower = message.lowercased()
            if context == "device" || lower.contains("device") {
                if lower.contains("maximum") || lower.contains("limit") {
                    return .maximumDevicesReached
                }
                return .deviceAlreadyRegistered
            } else if context == "certificate" || lower.contains("cert") {
                return .maximumCertificatesReached
            } else if context == "appId" || lower.contains("bundle") || lower.contains("identifier") || lower.contains("appid") || lower.contains("app id") {
                return .bundleIdentifierUnavailable
            }
            return .portalError(code: 35, message: message)
        default:
            return .portalError(code: code, message: message)
        }
    }
}
