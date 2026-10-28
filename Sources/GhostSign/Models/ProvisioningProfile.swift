//
//  ProvisioningProfile.swift
//  GhostSign
//
//  Represents an Apple Provisioning Profile (.mobileprovision).
//  Parses CMS envelope, extracts XML property list, entitlements, and metadata.
//

import Foundation
import GhostCode

public struct ProvisioningProfile: Sendable, Equatable, Identifiable {
    public var id: String { uuid.uuidString }
    public var identifier: String?
    public var name: String
    public var uuid: UUID
    public var bundleIdentifier: String
    public var teamIdentifier: String
    public var teamName: String
    public var creationDate: Date
    public var expirationDate: Date
    public var deviceIDs: [String]
    public var isFreeProvisioningProfile: Bool
    public var data: Data

    public var entitlements: [String: Any] {
        guard let dict = Self.dictionary(fromEncodedData: data),
              let ents = dict["Entitlements"] as? [String: Any] else {
            return [:]
        }
        return ents
    }

    public var isExpired: Bool {
        Date() > expirationDate
    }

    public init(
        name: String,
        uuid: UUID,
        bundleIdentifier: String,
        teamIdentifier: String,
        teamName: String = "",
        creationDate: Date = Date(),
        expirationDate: Date = Date().addingTimeInterval(7 * 86400),
        deviceIDs: [String] = [],
        isFreeProvisioningProfile: Bool = false,
        data: Data,
        identifier: String? = nil
    ) {
        self.name = name
        self.uuid = uuid
        self.bundleIdentifier = bundleIdentifier
        self.teamIdentifier = teamIdentifier
        self.teamName = teamName.isEmpty ? teamIdentifier : teamName
        self.creationDate = creationDate
        self.expirationDate = expirationDate
        self.deviceIDs = deviceIDs
        self.isFreeProvisioningProfile = isFreeProvisioningProfile
        self.data = data
        self.identifier = identifier
    }

    public init(data: Data) throws {
        guard let dict = Self.dictionary(fromEncodedData: data) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(codingPath: [], debugDescription: "Could not parse provisioning profile XML dictionary")
            )
        }

        let name = (dict["Name"] as? String) ?? "Provisioning Profile"
        let uuidString = (dict["UUID"] as? String) ?? UUID().uuidString
        let uuid = UUID(uuidString: uuidString) ?? UUID()

        let teamIdentifiers = dict["TeamIdentifier"] as? [String]
        let entitlementsDict = dict["Entitlements"] as? [String: Any] ?? [:]
        let teamID = teamIdentifiers?.first
            ?? (entitlementsDict["com.apple.developer.team-identifier"] as? String)
            ?? "UNKNOWN"

        let teamName = (dict["TeamName"] as? String) ?? teamID
        let creationDate = (dict["CreationDate"] as? Date) ?? Date()
        let expirationDate = (dict["ExpirationDate"] as? Date) ?? Date().addingTimeInterval(7 * 86400)
        let deviceIDs = (dict["ProvisionedDevices"] as? [String]) ?? []
        let isFree = (dict["LocalProvision"] as? Bool) ?? false

        var resolvedBundleID = "*"
        if let appID = entitlementsDict["application-identifier"] as? String {
            if let dotIndex = appID.firstIndex(of: ".") {
                resolvedBundleID = String(appID[appID.index(after: dotIndex)...])
            } else {
                resolvedBundleID = appID
            }
        }

        self.name = name
        self.uuid = uuid
        self.bundleIdentifier = resolvedBundleID
        self.teamIdentifier = teamID
        self.teamName = teamName
        self.creationDate = creationDate
        self.expirationDate = expirationDate
        self.deviceIDs = deviceIDs
        self.isFreeProvisioningProfile = isFree
        self.data = data
        self.identifier = nil
    }

    public init(url: URL) throws {
        let fileData = try Data(contentsOf: url)
        try self.init(data: fileData)
    }

    /// Matches the profile's bundleIdentifier against a target bundle identifier.
    /// Supports exact matches and wildcard patterns (e.g. `*` or `com.example.*`).
    public func matches(bundleIdentifier target: String) -> Bool {
        if bundleIdentifier == "*" {
            return true
        }
        if bundleIdentifier == target {
            return true
        }
        if bundleIdentifier.hasSuffix(".*") {
            let prefix = String(bundleIdentifier.dropLast(2))
            return target == prefix || target.hasPrefix(prefix + ".")
        }
        return false
    }

    /// Extracts the XML property list from encoded/CMS-signed .mobileprovision bytes.
    public static func dictionary(fromEncodedData data: Data) -> [String: Any]? {
        // Fast path: GhostSigner.provisioningProfileDictionary
        if let dict = GhostSigner.provisioningProfileDictionary(from: data) {
            return dict
        }

        // Fallback: UTF-8 / ASCII scan
        let str = String(decoding: data, as: UTF8.self)
        guard let startRange = str.range(of: "<?xml", options: .caseInsensitive) ?? str.range(of: "<plist", options: .caseInsensitive),
              let endRange = str.range(of: "</plist>", options: [.caseInsensitive, .backwards]),
              startRange.lowerBound < endRange.upperBound else {
            return nil
        }

        let xmlSubstring = str[startRange.lowerBound..<endRange.upperBound]
        guard let xmlData = xmlSubstring.data(using: .utf8),
              let plist = try? PropertyListSerialization.propertyList(from: xmlData, options: [], format: nil) as? [String: Any] else {
            return nil
        }
        return plist
    }

    /// Generates an in-memory Ad-Hoc / Fake-sign provisioning profile.
    /// Crucial for apps (such as SideStore) that verify `embedded.mobileprovision` existence on boot.
    public static func createAdHoc(
        bundleIdentifier: String,
        teamIdentifier: String = "ADHOC12345",
        teamName: String = "ContraStore Ad-Hoc",
        entitlements: [String: Any]? = nil
    ) -> ProvisioningProfile {
        let uuid = UUID()
        let now = Date()
        let tenYearsLater = now.addingTimeInterval(10 * 365 * 86400)

        var finalEntitlements: [String: Any] = entitlements ?? [:]
        if finalEntitlements["application-identifier"] == nil {
            finalEntitlements["application-identifier"] = "\(teamIdentifier).\(bundleIdentifier)"
        }
        if finalEntitlements["com.apple.developer.team-identifier"] == nil {
            finalEntitlements["com.apple.developer.team-identifier"] = teamIdentifier
        }
        if finalEntitlements["get-task-allow"] == nil {
            finalEntitlements["get-task-allow"] = true
        }
        if finalEntitlements["keychain-access-groups"] == nil {
            finalEntitlements["keychain-access-groups"] = ["\(teamIdentifier).*"]
        }

        let dict: [String: Any] = [
            "AppIDName": bundleIdentifier,
            "ApplicationIdentifierPrefix": [teamIdentifier],
            "CreationDate": now,
            "ExpirationDate": tenYearsLater,
            "Name": "Ad-Hoc Provisioning Profile",
            "TeamIdentifier": [teamIdentifier],
            "TeamName": teamName,
            "UUID": uuid.uuidString,
            "Entitlements": finalEntitlements,
            "ProvisionsAllDevices": true,
            "LocalProvision": true
        ]

        let plistData = (try? PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)) ?? Data()

        return ProvisioningProfile(
            name: "Ad-Hoc Provisioning Profile",
            uuid: uuid,
            bundleIdentifier: bundleIdentifier,
            teamIdentifier: teamIdentifier,
            teamName: teamName,
            creationDate: now,
            expirationDate: tenYearsLater,
            deviceIDs: [],
            isFreeProvisioningProfile: true,
            data: plistData
        )
    }
}

extension DeveloperProvisioningProfile {
    /// Converts a DeveloperPortal `DeveloperProvisioningProfile` into a `ProvisioningProfile`.
    public func toProvisioningProfile() throws -> ProvisioningProfile {
        var profile = try ProvisioningProfile(data: self.encodedProfile)
        profile.identifier = self.provisioningProfileId
        return profile
    }
}
