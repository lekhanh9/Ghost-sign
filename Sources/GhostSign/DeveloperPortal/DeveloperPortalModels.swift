//
//  DeveloperPortalModels.swift
//  GhostSign
//
//  Created for Ghost-Sign.
//

import Foundation

// MARK: - Team Types & Models

/// Classifies Apple Developer Program team types.
public enum DeveloperTeamType: String, Sendable, Codable, Equatable, Hashable {
    case organization = "Company/Organization"
    case individual   = "Individual"
    case free         = "Free"
    case unknown      = "Unknown"

    public var isPaid: Bool {
        self == .organization || self == .individual
    }
}

/// Represents a membership record within an Apple Developer Team.
public struct DeveloperMembership: Sendable, Codable, Equatable, Hashable {
    public let name: String
    public let status: String?
    public let membershipId: String?

    public init(name: String, status: String? = nil, membershipId: String? = nil) {
        self.name = name
        self.status = status
        self.membershipId = membershipId
    }
}

/// Represents an Apple Developer Team.
public struct DeveloperTeam: Sendable, Codable, Equatable, Hashable, Identifiable {
    public var id: String { teamId }
    public let teamId: String
    public let name: String
    public let type: String?
    public let status: String?
    public let memberships: [DeveloperMembership]?

    public var isFreeAccount: Bool {
        if let memberships = memberships, !memberships.isEmpty {
            return memberships.contains { $0.name.localizedCaseInsensitiveContains("free") }
        }
        return type?.localizedCaseInsensitiveContains("free") ?? false
    }

    public var teamType: DeveloperTeamType {
        if isFreeAccount {
            return .free
        }
        if type == DeveloperTeamType.organization.rawValue {
            return .organization
        }
        if type == DeveloperTeamType.individual.rawValue {
            return .individual
        }
        return .unknown
    }

    public init(
        teamId: String,
        name: String,
        type: String? = nil,
        status: String? = "active",
        memberships: [DeveloperMembership]? = nil
    ) {
        self.teamId = teamId
        self.name = name
        self.type = type
        self.status = status
        self.memberships = memberships
    }

    public init(
        teamId: String,
        name: String,
        teamType: DeveloperTeamType,
        status: String? = "active"
    ) {
        self.teamId = teamId
        self.name = name
        self.type = teamType.rawValue
        self.status = status
        if teamType == .free {
            self.memberships = [DeveloperMembership(name: "Free", status: "active")]
        } else {
            self.memberships = nil
        }
    }
}

// MARK: - Device Models

/// Represents a registered test hardware device on the Apple Developer Portal.
public struct DeveloperDevice: Sendable, Codable, Equatable, Hashable, Identifiable {
    public var id: String { deviceNumber.isEmpty ? (deviceId ?? UUID().uuidString) : deviceNumber }
    public let deviceId: String?
    public let deviceNumber: String // Hardware UDID
    public let name: String
    public let deviceClass: String?
    public let model: String?
    public let status: String?

    public var udid: String { deviceNumber }
    public var isActive: Bool { status == "c" || status == "active" }

    public init(
        deviceId: String? = nil,
        deviceNumber: String,
        name: String,
        deviceClass: String? = "iphone",
        model: String? = nil,
        status: String? = "c"
    ) {
        self.deviceId = deviceId
        self.deviceNumber = deviceNumber
        self.name = name
        self.deviceClass = deviceClass
        self.model = model
        self.status = status
    }

    public init(
        deviceId: String,
        deviceNumber: String,
        name: String,
        deviceClass: String? = "iphone",
        status: String? = "c"
    ) {
        self.init(deviceId: deviceId, deviceNumber: deviceNumber, name: name, deviceClass: deviceClass, model: nil, status: status)
    }
}

// MARK: - App ID Models

/// Represents an App ID (bundle identifier registration) on the Apple Developer Portal.
public struct DeveloperAppId: Sendable, Codable, Equatable, Hashable, Identifiable {
    public var id: String { appIdId }
    public let appIdId: String
    public let identifier: String // CFBundleIdentifier
    public let name: String
    public let prefix: String?
    public let isWildCard: Bool?

    public init(
        appIdId: String,
        identifier: String,
        name: String,
        prefix: String? = nil,
        isWildCard: Bool? = false
    ) {
        self.appIdId = appIdId
        self.identifier = identifier
        self.name = name
        self.prefix = prefix
        self.isWildCard = isWildCard
    }
}

// MARK: - Certificate Models

/// Represents an Apple Development or Distribution certificate.
/// Contains the raw in-memory DER bytes of the X.509 certificate in `certContent` (no Keychain storage).
public struct DeveloperCertificate: Sendable, Codable, Equatable, Hashable, Identifiable {
    public var id: String { certificateId ?? certRequestId ?? serialNumber ?? UUID().uuidString }
    public let certificateId: String?
    public let certRequestId: String?
    public let name: String?
    public let status: String?
    public let serialNumber: String?
    public let machineName: String?
    public let machineId: String?
    /// Raw binary DER bytes of the issued X.509 certificate.
    public let certContent: Data

    enum CodingKeys: String, CodingKey {
        case certificateId
        case certRequestId
        case name
        case status
        case serialNumber
        case serialNum
        case machineName
        case machineId
        case certContent
    }

    public init(
        certificateId: String? = nil,
        certRequestId: String? = nil,
        name: String? = nil,
        status: String? = "Active",
        serialNumber: String? = nil,
        machineName: String? = nil,
        machineId: String? = nil,
        certContent: Data = Data()
    ) {
        self.certificateId = certificateId
        self.certRequestId = certRequestId
        self.name = name
        self.status = status
        self.serialNumber = serialNumber
        self.machineName = machineName
        self.machineId = machineId
        self.certContent = certContent
    }

    public init(
        certificateId: String,
        name: String,
        status: String? = nil,
        serialNumber: String? = nil,
        machineName: String? = nil,
        machineId: String? = nil,
        certContent: Data = Data()
    ) {
        self.init(
            certificateId: certificateId,
            certRequestId: nil,
            name: name,
            status: status,
            serialNumber: serialNumber,
            machineName: machineName,
            machineId: machineId,
            certContent: certContent
        )
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.certificateId = try container.decodeIfPresent(String.self, forKey: .certificateId)
        self.certRequestId = try container.decodeIfPresent(String.self, forKey: .certRequestId)
        self.name = try container.decodeIfPresent(String.self, forKey: .name)
        self.status = try container.decodeIfPresent(String.self, forKey: .status)
        self.serialNumber = try container.decodeIfPresent(String.self, forKey: .serialNumber)
            ?? container.decodeIfPresent(String.self, forKey: .serialNum)
        self.machineName = try container.decodeIfPresent(String.self, forKey: .machineName)
        self.machineId = try container.decodeIfPresent(String.self, forKey: .machineId)
        if let data = try container.decodeIfPresent(Data.self, forKey: .certContent) {
            self.certContent = data
        } else {
            self.certContent = Data()
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(certificateId, forKey: .certificateId)
        try container.encodeIfPresent(certRequestId, forKey: .certRequestId)
        try container.encodeIfPresent(name, forKey: .name)
        try container.encodeIfPresent(status, forKey: .status)
        try container.encodeIfPresent(serialNumber, forKey: .serialNumber)
        try container.encodeIfPresent(machineName, forKey: .machineName)
        try container.encodeIfPresent(machineId, forKey: .machineId)
        if !certContent.isEmpty {
            try container.encode(certContent, forKey: .certContent)
        }
    }
}

// MARK: - Provisioning Profile Models

/// Represents a development or distribution provisioning profile.
/// Contains the complete in-memory binary PKCS#7 signed `.mobileprovision` payload in `encodedProfile`.
public struct DeveloperProvisioningProfile: Sendable, Codable, Equatable, Hashable, Identifiable {
    public var id: String { provisioningProfileId ?? uuid ?? UUID().uuidString }
    public let provisioningProfileId: String?
    public let name: String?
    public let status: String?
    public let type: String?
    public let distributionMethod: String?
    public let uuid: String?
    public let version: Int?
    public let isTeamProfile: Bool?
    public let appIdId: String?
    public let certificateIds: [String]?
    public let deviceIds: [String]?
    /// Complete PKCS#7 signed .mobileprovision binary payload.
    public let encodedProfile: Data
    public let dateExpire: Date?

    enum CodingKeys: String, CodingKey {
        case provisioningProfileId
        case name
        case status
        case type
        case distributionMethod
        case uuid = "UUID"
        case version
        case isTeamProfile
        case appIdId
        case certificateIds
        case deviceIds
        case encodedProfile
        case dateExpire
    }

    public init(
        provisioningProfileId: String? = nil,
        name: String? = nil,
        status: String? = "Active",
        type: String? = "iOS Development",
        distributionMethod: String? = "limited",
        uuid: String? = nil,
        version: Int? = nil,
        isTeamProfile: Bool? = true,
        appIdId: String? = nil,
        certificateIds: [String]? = nil,
        deviceIds: [String]? = nil,
        encodedProfile: Data = Data(),
        dateExpire: Date? = nil
    ) {
        self.provisioningProfileId = provisioningProfileId
        self.name = name
        self.status = status
        self.type = type
        self.distributionMethod = distributionMethod
        self.uuid = uuid
        self.version = version
        self.isTeamProfile = isTeamProfile
        self.appIdId = appIdId
        self.certificateIds = certificateIds
        self.deviceIds = deviceIds
        self.encodedProfile = encodedProfile
        self.dateExpire = dateExpire
    }


    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.provisioningProfileId = try container.decodeIfPresent(String.self, forKey: .provisioningProfileId)
        self.name = try container.decodeIfPresent(String.self, forKey: .name)
        self.status = try container.decodeIfPresent(String.self, forKey: .status)
        self.type = try container.decodeIfPresent(String.self, forKey: .type)
        self.distributionMethod = try container.decodeIfPresent(String.self, forKey: .distributionMethod)
        self.uuid = try container.decodeIfPresent(String.self, forKey: .uuid)
        self.version = try container.decodeIfPresent(Int.self, forKey: .version)
        self.isTeamProfile = try container.decodeIfPresent(Bool.self, forKey: .isTeamProfile)
        self.appIdId = try container.decodeIfPresent(String.self, forKey: .appIdId)
        self.certificateIds = try container.decodeIfPresent([String].self, forKey: .certificateIds)
        self.deviceIds = try container.decodeIfPresent([String].self, forKey: .deviceIds)

        if let data = try container.decodeIfPresent(Data.self, forKey: .encodedProfile) {
            self.encodedProfile = data
        } else {
            self.encodedProfile = Data()
        }

        if let date = try? container.decodeIfPresent(Date.self, forKey: .dateExpire) {
            self.dateExpire = date
        } else if let dateStr = try? container.decodeIfPresent(String.self, forKey: .dateExpire) {
            let iso = ISO8601DateFormatter()
            if let date = iso.date(from: dateStr) {
                self.dateExpire = date
            } else {
                let df = DateFormatter()
                df.locale = Locale(identifier: "en_US_POSIX")
                df.dateFormat = "yyyy-MM-dd HH:mm:ss"
                df.timeZone = TimeZone(secondsFromGMT: 0)
                self.dateExpire = df.date(from: dateStr)
            }
        } else {
            self.dateExpire = nil
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(provisioningProfileId, forKey: .provisioningProfileId)
        try container.encodeIfPresent(name, forKey: .name)
        try container.encodeIfPresent(status, forKey: .status)
        try container.encodeIfPresent(type, forKey: .type)
        try container.encodeIfPresent(distributionMethod, forKey: .distributionMethod)
        try container.encodeIfPresent(uuid, forKey: .uuid)
        try container.encodeIfPresent(version, forKey: .version)
        try container.encodeIfPresent(isTeamProfile, forKey: .isTeamProfile)
        try container.encodeIfPresent(appIdId, forKey: .appIdId)
        try container.encodeIfPresent(certificateIds, forKey: .certificateIds)
        try container.encodeIfPresent(deviceIds, forKey: .deviceIds)
        if !encodedProfile.isEmpty {
            try container.encode(encodedProfile, forKey: .encodedProfile)
        }
        try container.encodeIfPresent(dateExpire, forKey: .dateExpire)
    }
}

// MARK: - Response Envelopes

/// Top-level status envelope returned in all Apple Developer Services XML responses.
public struct DeveloperPortalStatusResponse: Decodable, Sendable {
    public let resultCode: Int?
    public let userString: String?
    public let resultString: String?
    public let errorString: String?
    public let creationTimestamp: String?

    public var isSuccess: Bool {
        resultCode == 0
    }

    public var effectiveErrorMessage: String {
        if let u = userString?.trimmingCharacters(in: .whitespacesAndNewlines), !u.isEmpty {
            return u
        }
        if let e = errorString?.trimmingCharacters(in: .whitespacesAndNewlines), !e.isEmpty {
            return e
        }
        if let r = resultString?.trimmingCharacters(in: .whitespacesAndNewlines), !r.isEmpty {
            return r
        }
        return "Apple Developer Services Error (\(resultCode ?? -1))"
    }
}

public struct ListTeamsResponse: Decodable, Sendable {
    public let resultCode: Int?
    public let userString: String?
    public let teams: [DeveloperTeam]?
}

public struct ListDevicesResponse: Decodable, Sendable {
    public let resultCode: Int?
    public let userString: String?
    public let devices: [DeveloperDevice]?
}

public struct DeviceResponse: Decodable, Sendable {
    public let resultCode: Int?
    public let userString: String?
    public let device: DeveloperDevice?
}

public struct ListAppIdsResponse: Decodable, Sendable {
    public let resultCode: Int?
    public let userString: String?
    public let appIds: [DeveloperAppId]?
}

public struct AppIdResponse: Decodable, Sendable {
    public let resultCode: Int?
    public let userString: String?
    public let appId: DeveloperAppId?
}

public struct ListCertificatesResponse: Decodable, Sendable {
    public let resultCode: Int?
    public let userString: String?
    public let certificates: [DeveloperCertificate]?
}

public struct CertificateResponse: Decodable, Sendable {
    public let resultCode: Int?
    public let userString: String?
    public let certRequest: DeveloperCertificate?
    public let certificate: DeveloperCertificate?

    public var effectiveCertificate: DeveloperCertificate? {
        certRequest ?? certificate
    }

    enum CodingKeys: String, CodingKey {
        case resultCode
        case userString
        case certRequest
        case certificate
    }
}

public struct ListProvisioningProfilesResponse: Decodable, Sendable {
    public let resultCode: Int?
    public let userString: String?
    public let provisioningProfiles: [DeveloperProvisioningProfile]?
}

public struct ProvisioningProfileResponse: Decodable, Sendable {
    public let resultCode: Int?
    public let userString: String?
    public let provisioningProfile: DeveloperProvisioningProfile?
}
