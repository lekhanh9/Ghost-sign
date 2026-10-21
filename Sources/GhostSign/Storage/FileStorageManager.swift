//
//  FileStorageManager.swift
//  GhostSign
//
//  Created for Ghost-Sign.
//  SideStore Sandbox Architecture (Issue #1647):
//  Stores .p12 certificates, .pem/.der keys, and .mobileprovision files as encrypted data inside the app sandbox (Documents).
//  Avoids Apple Keychain (SecItemAdd, SecIdentity) entirely.
//

import Foundation
@_exported import Crypto

public enum FileStorageError: LocalizedError, Equatable {
    case fileNotFound(URL)
    case writeFailed(URL, String)
    case readFailed(URL, String)
    case encryptionFailed(String)
    case decryptionFailed(String)
    case invalidData(String)

    public var errorDescription: String? {
        switch self {
        case .fileNotFound(let url):
            return "File not found at: \(url.path)"
        case .writeFailed(let url, let reason):
            return "Failed to write file to \(url.path): \(reason)"
        case .readFailed(let url, let reason):
            return "Failed to read file at \(url.path): \(reason)"
        case .encryptionFailed(let reason):
            return "Encryption error: \(reason)"
        case .decryptionFailed(let reason):
            return "Decryption error: \(reason)"
        case .invalidData(let reason):
            return "Invalid data format: \(reason)"
        }
    }
}

/// Manages filesystem-based storage for signing identities and provisioning profiles.
/// Follows SideStore's sandbox architecture (Issue #1647) where credentials are kept
/// in the app sandbox (e.g. Documents directory) with optional AES-GCM encryption at rest,
/// completely bypassing the system Keychain.
public final class FileStorageManager: @unchecked Sendable {
    public let baseDirectory: URL
    public let identitiesDirectory: URL
    public let profilesDirectory: URL

    /// Initializes a FileStorageManager with a custom or sandbox-default directory.
    ///
    /// - Parameter baseDirectory: Custom base URL. If nil, defaults to `Documents/GhostSign` (or tmp if Documents is unavailable).
    public init(baseDirectory: URL? = nil) {
        let root: URL
        if let baseDirectory = baseDirectory {
            root = baseDirectory
        } else {
            let docDirs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)
            if let first = docDirs.first {
                root = first.appendingPathComponent("GhostSign", isDirectory: true)
            } else {
                root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("GhostSign", isDirectory: true)
            }
        }
        self.baseDirectory = root
        self.identitiesDirectory = root.appendingPathComponent("Identities", isDirectory: true)
        self.profilesDirectory = root.appendingPathComponent("Profiles", isDirectory: true)

        try? createDirectoriesIfNeeded()
    }

    /// Ensures required subdirectories exist.
    public func createDirectoriesIfNeeded() throws {
        let fm = FileManager.default
        if !fm.fileExists(atPath: identitiesDirectory.path) {
            try fm.createDirectory(at: identitiesDirectory, withIntermediateDirectories: true)
        }
        if !fm.fileExists(atPath: profilesDirectory.path) {
            try fm.createDirectory(at: profilesDirectory, withIntermediateDirectories: true)
        }
    }

    // MARK: - Key Generation & Derivation Helpers

    /// Generates a cryptographically secure 256-bit AES symmetric key for local at-rest encryption.
    public static func generateKey() -> SymmetricKey {
        return SymmetricKey(size: .bits256)
    }

    /// Derives a 256-bit AES symmetric key from a user passphrase and salt using HKDF-SHA256.
    public static func deriveKey(from passphrase: String, salt: Data = Data("GhostSign.FileStorage.Salt".utf8)) -> SymmetricKey {
        let inputKey = SymmetricKey(data: Data(passphrase.utf8))
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKey,
            salt: salt,
            outputByteCount: 32
        )
    }

    // MARK: - Core Encryption & Decryption (AES-GCM)

    /// Encrypts raw data using AES-GCM (producing combined nonce + ciphertext + tag).
    public func encrypt(data: Data, key: SymmetricKey) throws -> Data {
        do {
            let sealedBox = try AES.GCM.seal(data, using: key)
            guard let combined = sealedBox.combined else {
                throw FileStorageError.encryptionFailed("Unable to extract combined sealed box data.")
            }
            return combined
        } catch let error as FileStorageError {
            throw error
        } catch {
            throw FileStorageError.encryptionFailed(error.localizedDescription)
        }
    }

    /// Decrypts AES-GCM data using the provided symmetric key.
    public func decrypt(data: Data, key: SymmetricKey) throws -> Data {
        do {
            let sealedBox = try AES.GCM.SealedBox(combined: data)
            return try AES.GCM.open(sealedBox, using: key)
        } catch {
            throw FileStorageError.decryptionFailed("Authentication tag or ciphertext invalid: \(error.localizedDescription)")
        }
    }

    // MARK: - Identity (.p12, .pem, .der) Storage

    /// Saves a PKCS#12 (.p12) archive into the Identities directory, optionally encrypted at rest.
    @discardableResult
    public func saveIdentity(
        p12Data: Data,
        filename: String = "identity.p12",
        encryptionKey: SymmetricKey? = nil
    ) throws -> URL {
        try createDirectoriesIfNeeded()
        let targetURL = identitiesDirectory.appendingPathComponent(filename)
        let finalData: Data
        if let key = encryptionKey {
            finalData = try encrypt(data: p12Data, key: key)
        } else {
            finalData = p12Data
        }

        do {
            try finalData.write(to: targetURL, options: .atomic)
            return targetURL
        } catch {
            throw FileStorageError.writeFailed(targetURL, error.localizedDescription)
        }
    }

    /// Loads the raw bytes of an identity file from disk, decrypting it if a key is provided.
    public func loadIdentity(
        from url: URL,
        decryptionKey: SymmetricKey? = nil
    ) throws -> Data {
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw FileStorageError.fileNotFound(url)
        }

        let rawData: Data
        do {
            rawData = try Data(contentsOf: url)
        } catch {
            throw FileStorageError.readFailed(url, error.localizedDescription)
        }

        if let key = decryptionKey {
            return try decrypt(data: rawData, key: key)
        } else {
            return rawData
        }
    }

    /// Loads a .p12 file, decrypts it in RAM, and parses the raw Private Key and Certificate into `RawIdentity`.
    /// Zero Keychain calls.
    public func loadRawIdentity(
        from url: URL,
        password: String = "",
        decryptionKey: SymmetricKey? = nil
    ) throws -> RawIdentity {
        let p12Data = try loadIdentity(from: url, decryptionKey: decryptionKey)
        return try PKCS12Parser.extract(p12Data: p12Data, password: password)
    }

    /// Saves a RawIdentity as PEM format files into the Identities directory.
    @discardableResult
    public func saveRawIdentityAsPEM(
        identity: RawIdentity,
        filename: String = "identity.pem",
        encryptionKey: SymmetricKey? = nil
    ) throws -> URL {
        let certPEM = identity.certificatePEM ?? RawIdentity.derToPEM(der: identity.certificateDER, type: "CERTIFICATE")
        let keyPEM = identity.privateKeyPEM ?? RawIdentity.derToPEM(der: identity.privateKeyDER, type: "RSA PRIVATE KEY")
        let fullPEM = "\(certPEM)\n\(keyPEM)\n"
        let data = Data(fullPEM.utf8)
        return try saveIdentity(p12Data: data, filename: filename, encryptionKey: encryptionKey)
    }

    // MARK: - Provisioning Profile (.mobileprovision) Storage

    /// Saves a `.mobileprovision` file into the Profiles directory, optionally encrypted at rest.
    @discardableResult
    public func saveProvisioningProfile(
        data: Data,
        filename: String = "embedded.mobileprovision",
        encryptionKey: SymmetricKey? = nil
    ) throws -> URL {
        try createDirectoriesIfNeeded()
        let targetURL = profilesDirectory.appendingPathComponent(filename)
        let finalData: Data
        if let key = encryptionKey {
            finalData = try encrypt(data: data, key: key)
        } else {
            finalData = data
        }

        do {
            try finalData.write(to: targetURL, options: .atomic)
            return targetURL
        } catch {
            throw FileStorageError.writeFailed(targetURL, error.localizedDescription)
        }
    }

    /// Reads and decrypts a `.mobileprovision` file from disk into RAM.
    public func loadProvisioningProfile(
        from url: URL,
        decryptionKey: SymmetricKey? = nil
    ) throws -> Data {
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw FileStorageError.fileNotFound(url)
        }

        let rawData: Data
        do {
            rawData = try Data(contentsOf: url)
        } catch {
            throw FileStorageError.readFailed(url, error.localizedDescription)
        }

        if let key = decryptionKey {
            return try decrypt(data: rawData, key: key)
        } else {
            return rawData
        }
    }

    // MARK: - Querying & Management

    /// Lists all stored identity files (e.g., .p12, .pem, .der).
    public func listStoredIdentities() throws -> [URL] {
        try createDirectoriesIfNeeded()
        let contents = try FileManager.default.contentsOfDirectory(at: identitiesDirectory, includingPropertiesForKeys: nil)
        return contents.filter { !$0.lastPathComponent.hasPrefix(".") }
    }

    /// Lists all stored provisioning profile files.
    public func listStoredProfiles() throws -> [URL] {
        try createDirectoriesIfNeeded()
        let contents = try FileManager.default.contentsOfDirectory(at: profilesDirectory, includingPropertiesForKeys: nil)
        return contents.filter { !$0.lastPathComponent.hasPrefix(".") }
    }

    /// Deletes a file at the given URL if it exists.
    public func deleteItem(at url: URL) throws {
        if FileManager.default.fileExists(atPath: url.path) {
            try FileManager.default.removeItem(at: url)
        }
    }

    /// Cleans up all stored identities and provisioning profiles.
    public func clearAll() throws {
        let fm = FileManager.default
        if fm.fileExists(atPath: identitiesDirectory.path) {
            try fm.removeItem(at: identitiesDirectory)
        }
        if fm.fileExists(atPath: profilesDirectory.path) {
            try fm.removeItem(at: profilesDirectory)
        }
        try createDirectoriesIfNeeded()
    }
}
