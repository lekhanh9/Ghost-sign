//
//  EntitlementModifier.swift
//  GhostSign
//
//  Harmonizes and dynamically rewrites iOS code signing entitlements.
//  Implements SideSign's proven keychain-access-groups Team ID prefix rewriting
//  and profile capability filtering to eliminate error -34018 and installation rejections.
//

import Foundation

public enum EntitlementModifier {

    /// Generates sanitized and transformed entitlements for a bundle against a target provisioning profile.
    public static func makeEntitlements(
        for bundle: AppBundle,
        profile: ProvisioningProfile?,
        bundleIDOverride: String? = nil
    ) -> [String: Any] {
        let targetBundleID = bundleIDOverride ?? bundle.bundleIdentifier
        let originalEntitlements = bundle.extractEmbeddedEntitlements() ?? [:]

        // MARK: - Case 1: Profile-guided signing (Apple ID / Developer Certificate)
        if let profile = profile {
            var targetEntitlements = profile.entitlements

            // 1. Rewrite Keychain Access Groups with new Team ID
            if let appKeychainGroups = originalEntitlements["keychain-access-groups"] as? [String] {
                let rewrittenGroups = appKeychainGroups.map { group -> String in
                    if let separator = group.firstIndex(of: ".") {
                        return profile.teamIdentifier + group[separator...]
                    } else {
                        return profile.teamIdentifier + "." + group
                    }
                }
                targetEntitlements["keychain-access-groups"] = rewrittenGroups
            }

            // 2. Harmonize Application Groups
            if let originalAppGroups = originalEntitlements["com.apple.security.application-groups"] as? [String] {
                if let profileAppGroups = targetEntitlements["com.apple.security.application-groups"] as? [String] {
                    let commonGroups = originalAppGroups.filter { profileAppGroups.contains($0) }
                    targetEntitlements["com.apple.security.application-groups"] = commonGroups.isEmpty ? profileAppGroups : commonGroups
                } else {
                    targetEntitlements["com.apple.security.application-groups"] = originalAppGroups
                }
            }

            // 3. Filter out capabilities that the original app never requested
            // (Unless it's an essential system identifier)
            for (key, _) in targetEntitlements {
                if originalEntitlements[key] == nil &&
                   key != "application-identifier" &&
                   key != "com.apple.developer.team-identifier" &&
                   key != "get-task-allow" {
                    targetEntitlements.removeValue(forKey: key)
                }
            }

            // 4. Set authoritative identity keys
            targetEntitlements["application-identifier"] = "\(profile.teamIdentifier).\(targetBundleID)"
            targetEntitlements["com.apple.developer.team-identifier"] = profile.teamIdentifier
            if targetEntitlements["get-task-allow"] == nil {
                targetEntitlements["get-task-allow"] = true
            }

            return targetEntitlements
        }

        // MARK: - Case 2: Ad-Hoc / Fake-sign signing (No Provisioning Profile)
        var adHocEntitlements = originalEntitlements
        adHocEntitlements["application-identifier"] = targetBundleID
        if adHocEntitlements["get-task-allow"] == nil {
            adHocEntitlements["get-task-allow"] = true
        }

        return adHocEntitlements
    }

    /// Serializes entitlements dictionary to UTF-8 XML property list Data.
    public static func makeEntitlementsXMLData(
        for bundle: AppBundle,
        profile: ProvisioningProfile?,
        bundleIDOverride: String? = nil
    ) throws -> Data {
        let dict = makeEntitlements(for: bundle, profile: profile, bundleIDOverride: bundleIDOverride)
        return try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
    }

    /// Serializes entitlements dictionary to UTF-8 XML property list String.
    public static func makeEntitlementsXMLString(
        for bundle: AppBundle,
        profile: ProvisioningProfile?,
        bundleIDOverride: String? = nil
    ) throws -> String {
        let data = try makeEntitlementsXMLData(for: bundle, profile: profile, bundleIDOverride: bundleIDOverride)
        guard let str = String(data: data, encoding: .utf8) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(codingPath: [], debugDescription: "Failed to convert entitlements plist to XML string")
            )
        }
        return str
    }
}
