//
//  SessionManager.swift
//  GhostSign
//
//  Secure, zero-Keychain session and token persistence engine.
//  Encrypts authentication tokens, DSID, IDMS credentials, and Anisette snapshots at rest
//  using AES-GCM-256 with PBKDF2 or machine-seeded hardware derivation.
//

import Foundation
import Crypto

public enum SessionStorageError: LocalizedError, Equatable {
    case fileNotFound(URL)
    case corruptedData(String)
    case invalidPassword
    case encryptionFailed(String)
    case decryptionFailed(String)

    public var errorDescription: String? {
        switch self {
        case .fileNotFound(let url):
            return "Session file not found at: \(url.path)"
        case .corruptedData(let reason):
            return "Corrupted session file: \(reason)"
        case .invalidPassword:
            return "Failed to decrypt session: invalid password or corrupted data."
        case .encryptionFailed(let reason):
            return "Session encryption error: \(reason)"
        case .decryptionFailed(let reason):
            return "Session decryption error: \(reason)"
        }
    }
}

/// Metadata description of a stored session without decrypting the payload.
public struct StoredSessionInfo: Sendable, Equatable, Identifiable {
    public var id: String { identifier ?? url.lastPathComponent }
    public let identifier: String?
    public let url: URL
    public let modificationDate: Date?

    public init(identifier: String?, url: URL, modificationDate: Date? = nil) {
        self.identifier = identifier
        self.url = url
        self.modificationDate = modificationDate
    }
}

public struct SessionManager: Sendable {

    // MARK: - Directory Resolution

    /// Standard directory for persisting session credentials.
    public static var defaultSessionDirectory: URL {
        let fm = FileManager.default
        #if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
        if let appSupport = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first {
            return appSupport
                .appendingPathComponent(Constants.SessionStorage.defaultDirName, isDirectory: true)
                .appendingPathComponent(Constants.SessionStorage.sessionSubdir, isDirectory: true)
        }
        if let docs = fm.urls(for: .documentDirectory, in: .userDomainMask).first {
            return docs
                .appendingPathComponent(Constants.SessionStorage.defaultDirName, isDirectory: true)
                .appendingPathComponent(Constants.SessionStorage.sessionSubdir, isDirectory: true)
        }
        #endif

        let env = ProcessInfo.processInfo.environment
        if let xdg = env["XDG_CONFIG_HOME"], !xdg.isEmpty {
            return URL(fileURLWithPath: xdg)
                .appendingPathComponent("ghostsign", isDirectory: true)
                .appendingPathComponent("sessions", isDirectory: true)
        }
        let home = env["HOME"] ?? NSHomeDirectory()
        return URL(fileURLWithPath: home, isDirectory: true)
            .appendingPathComponent(".ghostsign", isDirectory: true)
            .appendingPathComponent("sessions", isDirectory: true)
    }

    public static var defaultSessionURL: URL {
        defaultSessionDirectory.appendingPathComponent(Constants.SessionStorage.defaultFileName)
    }

    public static func url(for identifier: String? = nil, in directory: URL? = nil) -> URL {
        let dir = directory ?? defaultSessionDirectory
        if let id = identifier, !id.isEmpty {
            return dir.appendingPathComponent("\(Constants.SessionStorage.filePrefix)\(id)\(Constants.SessionStorage.fileExtension)")
        }
        return dir.appendingPathComponent(Constants.SessionStorage.defaultFileName)
    }

    public static func hasSession(identifier: String? = nil, in directory: URL? = nil) -> Bool {
        let target = url(for: identifier, in: directory)
        return FileManager.default.fileExists(atPath: target.path)
    }

    // MARK: - Save Session

    /// Encrypts and securely persists an AuthSession to disk without Apple Keychain.
    @discardableResult
    public static func save(
        _ session: AuthSession,
        identifier: String? = nil,
        directory: URL? = nil,
        password: String? = nil
    ) throws -> URL {
        let targetURL = url(for: identifier, in: directory)
        let parentDir = targetURL.deletingLastPathComponent()

        let fm = FileManager.default
        if !fm.fileExists(atPath: parentDir.path) {
            try fm.createDirectory(at: parentDir, withIntermediateDirectories: true)
        }

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let plainData: Data
        do {
            plainData = try encoder.encode(session)
        } catch {
            throw SessionStorageError.encryptionFailed("JSON encoding failed: \(error.localizedDescription)")
        }

        let salt = Data((0..<Constants.SessionStorage.saltLength).map { _ in UInt8.random(in: 0...255) })

        let key: SymmetricKey
        if let pwd = password, !pwd.isEmpty {
            guard let pwdData = pwd.data(using: .utf8),
                  let derived = CryptoUtilities.pbkdf2SHA256(
                    password: pwdData,
                    salt: salt,
                    rounds: Constants.SessionStorage.pbkdf2Rounds,
                    outputLength: Constants.SessionStorage.keyOutputLength
                  ) else {
                throw SessionStorageError.encryptionFailed("PBKDF2 key derivation failed.")
            }
            key = SymmetricKey(data: derived)
        } else {
            key = deriveMachineKey(salt: salt)
        }

        let sealedBox: AES.GCM.SealedBox
        do {
            sealedBox = try AES.GCM.seal(plainData, using: key)
        } catch {
            throw SessionStorageError.encryptionFailed(error.localizedDescription)
        }

        var outputData = Data()
        outputData.append(contentsOf: Constants.SessionStorage.magic)
        outputData.append(salt)
        outputData.append(Data(sealedBox.nonce))
        outputData.append(sealedBox.tag)
        outputData.append(sealedBox.ciphertext)

        try outputData.write(to: targetURL, options: .atomic)

        #if !os(Windows)
        try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: targetURL.path)
        #endif

        return targetURL
    }

    // MARK: - Load Session

    /// Loads and decrypts an AuthSession from disk.
    public static func load(
        identifier: String? = nil,
        from url: URL? = nil,
        password: String? = nil
    ) throws -> AuthSession {
        let targetURL = url ?? self.url(for: identifier)

        guard FileManager.default.fileExists(atPath: targetURL.path) else {
            throw SessionStorageError.fileNotFound(targetURL)
        }

        let fileData = try Data(contentsOf: targetURL)
        let headerSize = 4 + Constants.SessionStorage.saltLength + Constants.SessionStorage.nonceLength + Constants.SessionStorage.tagLength

        guard fileData.count > headerSize else {
            throw SessionStorageError.corruptedData("File size too small (\(fileData.count) bytes)")
        }

        let magic = Array(fileData[0..<4])
        guard magic == Constants.SessionStorage.magic else {
            throw SessionStorageError.corruptedData("Invalid magic header: \(magic)")
        }

        let saltOffset = 4
        let salt = fileData.subdata(in: saltOffset..<(saltOffset + Constants.SessionStorage.saltLength))

        let nonceOffset = saltOffset + Constants.SessionStorage.saltLength
        let nonceData = fileData.subdata(in: nonceOffset..<(nonceOffset + Constants.SessionStorage.nonceLength))

        let tagOffset = nonceOffset + Constants.SessionStorage.nonceLength
        let tag = fileData.subdata(in: tagOffset..<(tagOffset + Constants.SessionStorage.tagLength))

        let ciphertext = fileData.subdata(in: headerSize..<fileData.count)

        let key: SymmetricKey
        if let pwd = password, !pwd.isEmpty {
            guard let pwdData = pwd.data(using: .utf8),
                  let derived = CryptoUtilities.pbkdf2SHA256(
                    password: pwdData,
                    salt: salt,
                    rounds: Constants.SessionStorage.pbkdf2Rounds,
                    outputLength: Constants.SessionStorage.keyOutputLength
                  ) else {
                throw SessionStorageError.decryptionFailed("PBKDF2 key derivation failed.")
            }
            key = SymmetricKey(data: derived)
        } else {
            key = deriveMachineKey(salt: salt)
        }

        let nonce: AES.GCM.Nonce
        do {
            nonce = try AES.GCM.Nonce(data: nonceData)
        } catch {
            throw SessionStorageError.corruptedData("Invalid nonce data: \(error.localizedDescription)")
        }

        let sealedBox: AES.GCM.SealedBox
        do {
            sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        } catch {
            throw SessionStorageError.corruptedData("Invalid sealed box structure: \(error.localizedDescription)")
        }

        let decryptedData: Data
        do {
            decryptedData = try AES.GCM.open(sealedBox, using: key)
        } catch {
            throw SessionStorageError.invalidPassword
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        do {
            return try decoder.decode(AuthSession.self, from: decryptedData)
        } catch {
            throw SessionStorageError.corruptedData("Failed to decode AuthSession JSON: \(error.localizedDescription)")
        }
    }

    // MARK: - Query & Cleanup

    /// Lists all persisted session files found in the session directory.
    public static func listSessions(in directory: URL? = nil) -> [StoredSessionInfo] {
        let dir = directory ?? defaultSessionDirectory
        let fm = FileManager.default
        guard let files = try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: [.contentModificationDateKey]) else {
            return []
        }

        var results: [StoredSessionInfo] = []
        for file in files {
            let name = file.lastPathComponent
            let modDate = (try? file.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate

            if name == Constants.SessionStorage.defaultFileName {
                results.append(StoredSessionInfo(identifier: nil, url: file, modificationDate: modDate))
            } else if name.hasPrefix(Constants.SessionStorage.filePrefix) && name.hasSuffix(Constants.SessionStorage.fileExtension) {
                let id = String(name.dropFirst(Constants.SessionStorage.filePrefix.count).dropLast(Constants.SessionStorage.fileExtension.count))
                results.append(StoredSessionInfo(identifier: id, url: file, modificationDate: modDate))
            }
        }
        return results.sorted { ($0.identifier ?? "") < ($1.identifier ?? "") }
    }

    /// Deletes a persisted session file.
    public static func deleteSession(identifier: String? = nil, at url: URL? = nil) throws {
        let target = url ?? self.url(for: identifier)
        let fm = FileManager.default
        if fm.fileExists(atPath: target.path) {
            try fm.removeItem(at: target)
        }
    }

    /// Clears all session files in the directory.
    public static func clearAllSessions(in directory: URL? = nil) throws {
        let dir = directory ?? defaultSessionDirectory
        let fm = FileManager.default
        if fm.fileExists(atPath: dir.path) {
            try fm.removeItem(at: dir)
        }
    }

    // MARK: - Internal Hardware / Sandbox Seed Derivation

    private static func deriveMachineKey(salt: Data) -> SymmetricKey {
        var seedString = "GhostSign.MachineSeed.v1"
        let env = ProcessInfo.processInfo.environment
        if let user = env["USER"] ?? env["USERNAME"] {
            seedString.append(":\(user)")
        }
        let inputKey = SymmetricKey(data: Data(seedString.utf8))
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKey,
            salt: salt,
            outputByteCount: Constants.SessionStorage.keyOutputLength
        )
    }
}

// MARK: - Auth Extensions

extension AppleAuth {
    /// Saves an authenticated session into secure local storage.
    @discardableResult
    public func saveSession(
        _ session: AuthSession,
        identifier: String? = nil,
        password: String? = nil
    ) throws -> URL {
        try SessionManager.save(session, identifier: identifier, password: password)
    }

    /// Loads a stored session from secure local storage.
    public func loadSession(
        identifier: String? = nil,
        password: String? = nil
    ) throws -> AuthSession {
        try SessionManager.load(identifier: identifier, password: password)
    }

    /// Checks if a stored session exists.
    public func hasStoredSession(identifier: String? = nil) -> Bool {
        SessionManager.hasSession(identifier: identifier)
    }
}

extension AuthSession {
    /// Refreshes the Anisette attestation headers on this session using an Anisette provider.
    public mutating func refreshAnisette(using provider: AnisetteDataProvider) async throws {
        self.anisetteData = try await provider.fetchAnisetteData()
    }
}
