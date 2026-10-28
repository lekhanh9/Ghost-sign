//
//  BridgeSigner.swift
//  GhostSign
//
//  Bridges Ghost-Sign (Apple Auth & Certificate Management) with Ghost-Code (Mach-O Signing Engine).
//  STRICT ARCHITECTURE DIRECTIVE: Uses In-Memory Raw Crypto (Data). Never touches Apple Keychain.
//  Incorporates SideSign & ReProvision Reborn multi-bundle extension matching, dynamic keychain
//  access group rewriting, and archive packaging.
//

import Foundation
import GhostCode
import Crypto

// MARK: - Global Convenience APIs

/// Signs an application bundle (.app) or archive (.ipa) using raw in-memory Certificate and Private Key data.
public func signBundleWithRawIdentity(
    ipaPath: URL,
    certificateDER: Data,
    privateKeyDER: Data,
    provisionPath: URL,
    outputPath: URL
) throws {
    let bridge = BridgeSigner()
    try bridge.signApp(
        targetPath: ipaPath,
        certificateDER: certificateDER,
        privateKeyDER: privateKeyDER,
        provisionPaths: [provisionPath],
        outputPath: outputPath
    )
}

/// Signs an application bundle (.app) or archive (.ipa) using a .p12 archive decrypted in memory (No Keychain).
public func signBundleWithCertificate(
    ipaPath: URL,
    p12Path: URL,
    password: String,
    provisionPath: URL,
    outputPath: URL
) throws {
    let bridge = BridgeSigner()
    try bridge.signApp(
        targetPath: ipaPath,
        p12Path: p12Path,
        password: password,
        provisionPaths: [provisionPath],
        outputPath: outputPath
    )
}

/// Signs an application bundle (.app) or archive (.ipa) using stored identity from FileStorageManager.
public func signBundleWithStoredIdentity(
    ipaPath: URL,
    p12FileURL: URL,
    password: String = "",
    storageManager: FileStorageManager = FileStorageManager(),
    decryptionKey: SymmetricKey? = nil,
    provisionPath: URL,
    outputPath: URL
) throws {
    let bridge = BridgeSigner()
    try bridge.signBundleWithStoredIdentity(
        ipaPath: ipaPath,
        p12FileURL: p12FileURL,
        password: password,
        storageManager: storageManager,
        decryptionKey: decryptionKey,
        provisionPath: provisionPath,
        outputPath: outputPath
    )
}

/// Signs an application bundle (.app) or archive (.ipa) directly using models returned by DeveloperPortalClient.
public func signBundleWithDeveloperPortalAssets(
    ipaPath: URL,
    certificate: DeveloperCertificate,
    privateKeyDER: Data,
    profile: DeveloperProvisioningProfile,
    outputPath: URL
) throws {
    let bridge = BridgeSigner()
    try bridge.signBundleWithDeveloperPortalAssets(
        ipaPath: ipaPath,
        certificate: certificate,
        privateKeyDER: privateKeyDER,
        profile: profile,
        outputPath: outputPath
    )
}

// MARK: - BridgeSigner Implementation

public final class BridgeSigner: @unchecked Sendable {
    public init() {}

    // MARK: - Comprehensive Signing Pipelines

    /// Core signing engine supporting .app directories, .ipa archives, multi-bundle extension profiles,
    /// dynamic keychain rewriting, and custom bundle ID overrides.
    public func signApp(
        targetPath: URL,
        certificateDER: Data?,
        privateKeyDER: Data?,
        provisioningProfiles: [ProvisioningProfile] = [],
        bundleIDOverride: String? = nil,
        outputPath: URL? = nil
    ) throws {
        let fm = FileManager.default
        let isArchive = ArchiveHelper.isIPA(url: targetPath)

        let workingDir = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try fm.createDirectory(at: workingDir, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: workingDir) }

        // 1. Resolve .app bundle URL
        let appURL: URL
        if isArchive {
            appURL = try ArchiveHelper.unpack(ipaURL: targetPath, to: workingDir)
        } else {
            appURL = targetPath
        }

        guard let appBundle = AppBundle(fileURL: appURL) else {
            throw MachOWriterError.fileWriteError("Failed to parse AppBundle at \(appURL.path)")
        }

        // 2. Profile resolution helper
        func resolveProfile(for bundle: AppBundle) -> ProvisioningProfile? {
            if let exact = provisioningProfiles.first(where: { $0.bundleIdentifier == bundle.bundleIdentifier }) {
                return exact
            }
            if let wildcard = provisioningProfiles.first(where: { $0.matches(bundleIdentifier: bundle.bundleIdentifier) }) {
                return wildcard
            }
            return provisioningProfiles.first ?? bundle.provisioningProfile
        }

        let mainProfile = resolveProfile(for: appBundle)
        let effectiveTeamID = mainProfile?.teamIdentifier
            ?? (mainProfile?.entitlements["com.apple.developer.team-identifier"] as? String)

        let signer = GhostSigner()

        // 3. Bottom-Up Step A: Sign all Frameworks with empty entitlements
        for frameworkURL in appBundle.frameworks {
            let frameworkExeName = frameworkURL.deletingPathExtension().lastPathComponent
            let frameworkExeURL = frameworkURL.appendingPathComponent(frameworkExeName)
            if fm.fileExists(atPath: frameworkExeURL.path) {
                try signer.sign(
                    binaryURL: frameworkExeURL,
                    identifier: frameworkExeName,
                    entitlements: nil,
                    rawCertificate: certificateDER,
                    rawPrivateKey: privateKeyDER,
                    teamID: effectiveTeamID
                )
            }
        }

        // 4. Bottom-Up Step B: Sign all Dylibs with empty entitlements
        for dylibURL in appBundle.dylibs {
            let dylibName = dylibURL.deletingPathExtension().lastPathComponent
            try signer.sign(
                binaryURL: dylibURL,
                identifier: dylibName,
                entitlements: nil,
                rawCertificate: certificateDER,
                rawPrivateKey: privateKeyDER,
                teamID: effectiveTeamID
            )
        }

        // 5. Bottom-Up Step C: Sign all App Extensions (.appex)
        for ext in appBundle.appExtensions {
            let extProfile = resolveProfile(for: ext)

            // Inject matching mobileprovision if present
            if let extProfile = extProfile {
                let extProvURL = ext.fileURL.appendingPathComponent("embedded.mobileprovision")
                if fm.fileExists(atPath: extProvURL.path) {
                    try? fm.removeItem(at: extProvURL)
                }
                try extProfile.data.write(to: extProvURL)
            }

            // Generate harmonized entitlements for this extension
            let extEntitlements = EntitlementModifier.makeEntitlements(for: ext, profile: extProfile)

            // Seal extension bundle
            let extCodeResources = try BundleSealer.generateCodeResources(for: ext.fileURL, executableName: ext.executableName)

            // Sign extension executable
            if let extExeURL = ext.executableURL {
                var extExeData = try Data(contentsOf: extExeURL)
                try signer.sign(
                    binaryData: &extExeData,
                    identifier: ext.bundleIdentifier,
                    entitlements: extEntitlements,
                    rawCertificate: certificateDER,
                    rawPrivateKey: privateKeyDER,
                    infoPlistData: try? Data(contentsOf: ext.infoPlistURL),
                    resourceDirData: extCodeResources,
                    teamID: extProfile?.teamIdentifier ?? effectiveTeamID
                )
                try extExeData.write(to: extExeURL)
            }
        }

        // 6. Bottom-Up Step D: Sign Root Application Bundle
        if let newBundleID = bundleIDOverride, newBundleID != appBundle.bundleIdentifier {
            var plist = appBundle.infoPlist
            plist["CFBundleIdentifier"] = newBundleID
            let updatedData = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
            try updatedData.write(to: appBundle.infoPlistURL)
        }

        // Inject root mobileprovision
        if let mainProfile = mainProfile {
            let rootProvURL = appBundle.fileURL.appendingPathComponent("embedded.mobileprovision")
            if fm.fileExists(atPath: rootProvURL.path) {
                try? fm.removeItem(at: rootProvURL)
            }
            try mainProfile.data.write(to: rootProvURL)
        }

        // Generate harmonized entitlements for root application
        let rootEntitlements = EntitlementModifier.makeEntitlements(
            for: appBundle,
            profile: mainProfile,
            bundleIDOverride: bundleIDOverride
        )

        // Seal root application bundle
        let rootCodeResources = try BundleSealer.generateCodeResources(
            for: appBundle.fileURL,
            executableName: appBundle.executableName
        )

        // Sign main executable
        guard let mainExeURL = appBundle.executableURL else {
            throw MachOWriterError.fileWriteError("Missing main executable in bundle at \(appBundle.fileURL.path)")
        }

        var mainExeData = try Data(contentsOf: mainExeURL)
        try signer.sign(
            binaryData: &mainExeData,
            identifier: bundleIDOverride ?? appBundle.bundleIdentifier,
            entitlements: rootEntitlements,
            rawCertificate: certificateDER,
            rawPrivateKey: privateKeyDER,
            infoPlistData: try? Data(contentsOf: appBundle.infoPlistURL),
            resourceDirData: rootCodeResources,
            teamID: effectiveTeamID
        )
        try mainExeData.write(to: mainExeURL)

        // 7. Output Delivery
        let destination = outputPath ?? targetPath
        let outputIsIPA = ArchiveHelper.isIPA(url: destination)

        if outputIsIPA {
            try ArchiveHelper.repack(appURL: appBundle.fileURL, to: destination)
        } else if destination != appBundle.fileURL {
            if fm.fileExists(atPath: destination.path) {
                try? fm.removeItem(at: destination)
            }
            try fm.copyItem(at: appBundle.fileURL, to: destination)
        }
    }

    /// Convenience wrapper taking an array of provisioning profile file URLs.
    public func signApp(
        targetPath: URL,
        certificateDER: Data?,
        privateKeyDER: Data?,
        provisionPaths: [URL],
        bundleIDOverride: String? = nil,
        outputPath: URL? = nil
    ) throws {
        let profiles = provisionPaths.compactMap { try? ProvisioningProfile(url: $0) }
        try signApp(
            targetPath: targetPath,
            certificateDER: certificateDER,
            privateKeyDER: privateKeyDER,
            provisioningProfiles: profiles,
            bundleIDOverride: bundleIDOverride,
            outputPath: outputPath
        )
    }

    /// Convenience wrapper using .p12 archive path and password.
    public func signApp(
        targetPath: URL,
        p12Path: URL,
        password: String,
        provisionPaths: [URL],
        bundleIDOverride: String? = nil,
        outputPath: URL? = nil
    ) throws {
        let p12Data = try Data(contentsOf: p12Path)
        let identity = try PKCS12Parser.extract(p12Data: p12Data, password: password)
        try signApp(
            targetPath: targetPath,
            certificateDER: identity.certificateDER,
            privateKeyDER: identity.privateKeyDER,
            provisionPaths: provisionPaths,
            bundleIDOverride: bundleIDOverride,
            outputPath: outputPath
        )
    }

    // MARK: - Backward-Compatible APIs

    public func signBundleWithRawIdentity(
        ipaPath: URL,
        certificateDER: Data,
        privateKeyDER: Data,
        provisionPath: URL,
        outputPath: URL
    ) throws {
        try signApp(
            targetPath: ipaPath,
            certificateDER: certificateDER,
            privateKeyDER: privateKeyDER,
            provisionPaths: [provisionPath],
            outputPath: outputPath
        )
    }

    public func signBundleWithCertificate(
        ipaPath: URL,
        p12Path: URL,
        password: String,
        provisionPath: URL,
        outputPath: URL
    ) throws {
        try signApp(
            targetPath: ipaPath,
            p12Path: p12Path,
            password: password,
            provisionPaths: [provisionPath],
            outputPath: outputPath
        )
    }

    public func signBundleWithStoredIdentity(
        ipaPath: URL,
        p12FileURL: URL,
        password: String = "",
        storageManager: FileStorageManager = FileStorageManager(),
        decryptionKey: SymmetricKey? = nil,
        provisionPath: URL,
        outputPath: URL
    ) throws {
        let rawIdentity: RawIdentity
        let ext = p12FileURL.pathExtension.lowercased()
        if ext == "pem" {
            let data = try storageManager.loadIdentity(from: p12FileURL, decryptionKey: decryptionKey)
            guard let pemString = String(data: data, encoding: .utf8),
                  let identity = RawIdentity.parsePEMIdentity(pemString: pemString) else {
                throw FileStorageError.invalidData("Could not parse PEM identity from \(p12FileURL.lastPathComponent)")
            }
            rawIdentity = identity
        } else {
            rawIdentity = try storageManager.loadRawIdentity(
                from: p12FileURL,
                password: password,
                decryptionKey: decryptionKey
            )
        }

        try signApp(
            targetPath: ipaPath,
            certificateDER: rawIdentity.certificateDER,
            privateKeyDER: rawIdentity.privateKeyDER,
            provisionPaths: [provisionPath],
            outputPath: outputPath
        )
    }

    public func signBundleWithDeveloperPortalAssets(
        ipaPath: URL,
        certificate: DeveloperCertificate,
        privateKeyDER: Data,
        profile: DeveloperProvisioningProfile,
        outputPath: URL
    ) throws {
        let parsedProfile = try profile.toProvisioningProfile()
        try signApp(
            targetPath: ipaPath,
            certificateDER: certificate.certContent,
            privateKeyDER: privateKeyDER,
            provisioningProfiles: [parsedProfile],
            outputPath: outputPath
        )
    }
}
