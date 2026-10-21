//
//  BridgeSigner.swift
//  GhostSign
//
//  Bridges Ghost-Sign (Apple Auth & Certificate Management) with Ghost-Code (Mach-O Signing Engine).
//  STRICT ARCHITECTURE DIRECTIVE: Uses In-Memory Raw Crypto (Data). Never touches Apple Keychain.
//

import Foundation
import GhostCode
import Crypto

/// Top-level signing bridge function using in-memory raw Certificate & Private Key data.
public func signBundleWithRawIdentity(
    ipaPath: URL,
    certificateDER: Data,
    privateKeyDER: Data,
    provisionPath: URL,
    outputPath: URL
) throws {
    let bridge = BridgeSigner()
    try bridge.signBundleWithRawIdentity(
        ipaPath: ipaPath,
        certificateDER: certificateDER,
        privateKeyDER: privateKeyDER,
        provisionPath: provisionPath,
        outputPath: outputPath
    )
}

/// Top-level signing bridge function to sign an application bundle using a .p12 identity.
/// Decrypts .p12 in memory to extract raw Data without saving to Apple Keychain.
public func signBundleWithCertificate(
    ipaPath: URL,
    p12Path: URL,
    password: String,
    provisionPath: URL,
    outputPath: URL
) throws {
    let bridge = BridgeSigner()
    try bridge.signBundleWithCertificate(
        ipaPath: ipaPath,
        p12Path: p12Path,
        password: password,
        provisionPath: provisionPath,
        outputPath: outputPath
    )
}

/// Top-level signing bridge function using stored identity from FileStorageManager (SideStore sandbox model).
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

/// Top-level signing bridge function using assets fetched from DeveloperPortalClient directly in RAM.
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

public final class BridgeSigner {
    public init() {}

    /// Signs an application bundle or extracted IPA using in-memory raw Certificate and Private Key Data (No Keychain).
    public func signBundleWithRawIdentity(
        ipaPath: URL,
        certificateDER: Data,
        privateKeyDER: Data,
        provisionPath: URL,
        outputPath: URL
    ) throws {
        // MARK: - Step 1: Provisioning Profile & Entitlements
        var entitlements: [String: Any]? = nil
        if let provisionData = try? Data(contentsOf: provisionPath) {
            entitlements = GhostSigner.extractEntitlements(fromMobileProvisionData: provisionData)
        }

        // MARK: - Step 2: Invoke Ghost-Code Engine with Raw Data
        // Passes raw Private Key and Certificate Data directly to Ghost-Code (No Keychain)
        let signer = GhostSigner()
        try signer.signBundle(
            appURL: ipaPath,
            provisioningProfileURL: provisionPath,
            rawCertificate: certificateDER,
            rawPrivateKey: privateKeyDER,
            entitlements: entitlements
        )

        // MARK: - Step 3: Output Delivery
        if outputPath != ipaPath && FileManager.default.fileExists(atPath: ipaPath.path) {
            if FileManager.default.fileExists(atPath: outputPath.path) {
                try? FileManager.default.removeItem(at: outputPath)
            }
            try FileManager.default.copyItem(at: ipaPath, to: outputPath)
        }
    }

    /// Signs an application bundle using a .p12 archive by decrypting it in RAM (No Keychain).
    public func signBundleWithCertificate(
        ipaPath: URL,
        p12Path: URL,
        password: String,
        provisionPath: URL,
        outputPath: URL
    ) throws {
        // MARK: - Step 1: In-Memory PKCS#12 Decryption
        let p12Data = try Data(contentsOf: p12Path)
        let identity = try PKCS12Parser.extract(p12Data: p12Data, password: password)

        // MARK: - Step 2: Sign using raw in-memory identity
        try signBundleWithRawIdentity(
            ipaPath: ipaPath,
            certificateDER: identity.certificateDER,
            privateKeyDER: identity.privateKeyDER,
            provisionPath: provisionPath,
            outputPath: outputPath
        )
    }

    /// Signs an application bundle using an encrypted/stored identity from sandbox file storage (No Keychain).
    public func signBundleWithStoredIdentity(
        ipaPath: URL,
        p12FileURL: URL,
        password: String = "",
        storageManager: FileStorageManager = FileStorageManager(),
        decryptionKey: SymmetricKey? = nil,
        provisionPath: URL,
        outputPath: URL
    ) throws {
        // MARK: - Step 1: Read and decrypt from sandbox storage in RAM
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

        // MARK: - Step 2: Pass raw Data directly to Ghost-Code Mach-O signer
        try signBundleWithRawIdentity(
            ipaPath: ipaPath,
            certificateDER: rawIdentity.certificateDER,
            privateKeyDER: rawIdentity.privateKeyDER,
            provisionPath: provisionPath,
            outputPath: outputPath
        )
    }

    /// Signs an application bundle directly using models returned by DeveloperPortalClient.
    public func signBundleWithDeveloperPortalAssets(
        ipaPath: URL,
        certificate: DeveloperCertificate,
        privateKeyDER: Data,
        profile: DeveloperProvisioningProfile,
        outputPath: URL
    ) throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let tempProfileURL = tempDir.appendingPathComponent("embedded.mobileprovision")
        try profile.encodedProfile.write(to: tempProfileURL)

        try signBundleWithRawIdentity(
            ipaPath: ipaPath,
            certificateDER: certificate.certContent,
            privateKeyDER: privateKeyDER,
            provisionPath: tempProfileURL,
            outputPath: outputPath
        )
    }
}
