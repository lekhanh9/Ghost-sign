//
//  Constants.swift
//  GhostSign
//
//  Centralized constants for Apple GrandSlam authentication, Developer Services 2 (QH65B2),
//  Anisette headers, sandbox storage, result codes, and HTTP statuses.
//

import Foundation

public enum GhostSignConstants {

    // MARK: - Apple GrandSlam & iCloud Authentication

    public enum GrandSlam {
        public static let service        = "iCloud"
        public static let headerVersion  = "1.0.1"
        public static let authApp        = "com.apple.gs.xcode.auth"
    }

    // MARK: - Apple AuthKit & IDMS

    public enum AppleAuth {
        public static let appIDKey       = "ba2ec180e6ca6e6c6a542255453b24d6e6e5b2be0cc48bc1b0d8ad64cfe0228f"
    }

    // MARK: - Apple Developer Services 2 (QH65B2)

    public enum DeveloperServices {
        public static let clientID                = "XABBG36SBA"
        public static let protocolVersion         = "QH65B2"
        public static let servicesProtocolVersion = "v1"
        public static let xcodeVersion            = "15.4 (15F31d)"
        public static let appInfo                 = "com.apple.gs.xcode.auth"
        public static let defaultBaseURL          = "https://developerservices2.apple.com/services/QH65B2"
        public static let defaultAccountRepairMessage = """
        Your Apple ID requires account verification or terms agreement.
        Please sign in to developer.apple.com or appleid.apple.com.
        """
    }

    // MARK: - API URLs & Endpoints

    public enum URLs {
        // Base Services URLs
        public static let grandSlamAuth             = "https://gsa.apple.com/grandslam/GsService2"
        public static let grandSlamValidate         = "https://gsa.apple.com/grandslam/GsService2/validate"
        public static let trustedDevice             = "https://gsa.apple.com/auth/verify/trusteddevice"
        public static let phoneBase                 = "https://gsa.apple.com/auth/verify/phone"
        public static let appleAuthDevices          = "https://idmsa.apple.com/appleauth/auth/devices"
        public static let developerAccount          = "https://developer.apple.com/account"
        public static let developerServicesBase     = "https://developerservices2.apple.com/services/QH65B2"

        // Developer Portal Actions
        public static let viewDeveloper             = "viewDeveloper.action"
        public static let listTeams                 = "listTeams.action"
        public static let listDevices               = "ios/listDevices.action"
        public static let addDevice                 = "ios/addDevice.action"
        public static let updateDevice              = "ios/updateDevice.action"
        public static let deleteDevice              = "ios/deleteDevice.action"
        public static let listAppIDs                = "ios/listAppIds.action"
        public static let addAppID                  = "ios/addAppId.action"
        public static let updateAppID               = "ios/updateAppId.action"
        public static let deleteAppID               = "ios/deleteAppId.action"
        public static let listApplicationGroups     = "ios/listApplicationGroups.action"
        public static let addApplicationGroup       = "ios/addApplicationGroup.action"
        public static let updateApplicationGroup    = "ios/updateApplicationGroup.action"
        public static let assignApplicationGroup    = "ios/assignApplicationGroupToAppId.action"
        public static let deleteApplicationGroup    = "ios/deleteApplicationGroup.action"
        public static let listCertificates          = "ios/listAllDevelopmentCerts.action"
        public static let submitCSR                 = "ios/submitDevelopmentCSR.action"
        public static let submitDevelopmentCSR      = "ios/submitDevelopmentCSR.action"
        public static let submitDistributionCSR     = "ios/submitDistributionCSR.action"
        public static let listProvisioningProfiles  = "ios/listProvisioningProfiles.action"
        public static let downloadTeamProfile       = "ios/downloadTeamProvisioningProfile.action"
        public static let downloadProfile           = "ios/downloadProvisioningProfile.action"
        public static let createProvisioningProfile = "ios/createProvisioningProfile.action"
        public static let regenProvisioningProfile  = "ios/regenProvisioningProfile.action"
        public static let deleteProvisioningProfile = "ios/deleteProvisioningProfile.action"
    }

    // MARK: - Anisette Header Keys

    public enum AnisetteHeaders {
        public static let machineID        = "X-Apple-I-MD-M"
        public static let oneTimePassword  = "X-Apple-I-MD"
        public static let localUserID      = "X-Apple-I-MD-LU"
        public static let routingInfo      = "X-Apple-I-MD-RINFO"
        public static let deviceID         = "X-Mme-Device-Id"
        public static let serialNumber     = "X-Apple-I-SRL-NO"
        public static let clientTime       = "X-Apple-I-Client-Time"
        public static let timeZone         = "X-Apple-I-TimeZone"
        public static let locale           = "X-Apple-Locale"
        public static let identityId       = "X-Apple-I-Identity-Id"
        public static let gsToken          = "X-Apple-GS-Token"
        public static let appInfo          = "X-Apple-App-Info"
        public static let xcodeVersion     = "X-Xcode-Version"
        public static let mmeClientInfo    = "X-MMe-Client-Info"
        public static let appleClientInfo  = "X-Apple-I-Client-Info"
    }

    // MARK: - Anisette Defaults

    public enum Anisette {
        public static let defaultServerURL  = "https://ani.sidestore.io"
        public static let defaultRoutingInfo = "17106176"
    }

    // MARK: - Session Storage Constants

    public enum SessionStorage {
        public static let magic: [UInt8]     = [0x47, 0x53, 0x53, 0x31] // "GSS1"
        public static let defaultFileName    = "session.dat"
        public static let filePrefix         = "session_"
        public static let fileExtension      = ".dat"
        public static let saltLength         = 16
        public static let nonceLength        = 12
        public static let tagLength          = 16
        public static let pbkdf2Rounds       = 100_000
        public static let keyOutputLength    = 32
        public static let defaultDirName     = "GhostSign"
        public static let sessionSubdir      = "Sessions"
    }

    // MARK: - Developer Portal Result Codes

    public enum ResultCodes {
        public static let success                             = 0
        public static let invalidCertificateRequest           = 3250
        public static let deviceAlreadyRegistered             = 35
        public static let maximumCertificatesReached          = 35
        public static let bundleIdentifierUnavailable         = 35
        public static let maximumDevicesReached               = 35
        public static let appGroupDoesNotExist                = 35
        public static let maximumAppIDLimitReached            = 37
        public static let maximumCertificatesReachedAlternate = 7460
        public static let profileNotFoundAlternate            = 8201
        public static let profileNotFound                     = 9115
        public static let sessionExpired                      = -22406
    }

    // MARK: - GrandSlam Auth Error Codes

    public enum GrandSlamErrorCodes {
        public static let incorrectCredentials                = -22406
        public static let appSpecificPasswordRequired         = -20101
        public static let appSpecificPasswordRequiredFallback = -20209
        public static let incorrectVerificationCode           = -21669
        public static let tooManyCodesRequested               = -20102
        public static let tooManyAttempts                     = -21668
        public static let stepUpVerificationRequired          = -22411
        public static let rateLimited                         = -22411
    }

    // MARK: - Storage Directories & Extensions

    public enum Storage {
        public static let defaultBaseDirectoryName = "GhostSign"
        public static let identitiesDirectoryName  = "Identities"
        public static let profilesDirectoryName    = "Profiles"
        public static let p12Extension             = "p12"
        public static let cerExtension             = "cer"
        public static let mobileprovisionExtension = "mobileprovision"
        public static let pemExtension             = "pem"
        public static let derExtension             = "der"
    }

    // MARK: - Cryptographic Parameters

    public enum Crypto {
        public static let defaultRSAKeyBits        = 2048
        public static let pbkdf2DefaultIterations  = 100_000
        public static let aesGCMNonceBytes         = 12
        public static let aesGCMTagBytes           = 16
        public static let saltBytes                = 16
    }

    // MARK: - HTTP Status Codes

    public enum HTTPStatusCodes {
        public static let ok                  = 200
        public static let noContent           = 204
        public static let badRequest          = 400
        public static let unauthorized        = 401
        public static let forbidden           = 403
        public static let notFound            = 404
        public static let tooManyRequests     = 429
        public static let internalServerError = 500
        public static let badGateway          = 502
        public static let serviceUnavailable  = 503
        public static let gatewayTimeout      = 504

        public static func localizedDescription(for statusCode: Int) -> String {
            switch statusCode {
            case badRequest:
                return "The server rejected the request parameters."
            case unauthorized:
                return "Your sign-in session expired or is unauthorized."
            case forbidden:
                return "Access to this Apple Developer service was denied."
            case notFound:
                return "The requested Apple service endpoint could not be found."
            case tooManyRequests:
                return "Too many requests sent to Apple. Please wait a few moments and try again."
            case internalServerError:
                return "Apple's authentication servers encountered an internal error."
            case badGateway:
                return "Apple's servers received an invalid gateway response."
            case serviceUnavailable:
                return "Apple Developer Portal is temporarily unavailable or undergoing maintenance."
            case gatewayTimeout:
                return "Apple's servers took too long to respond (connection timed out)."
            default:
                return "Apple service returned an unexpected error (HTTP \(statusCode))."
            }
        }
    }
}

/// Global alias for convenient access to GhostSign constants.
public typealias Constants = GhostSignConstants
