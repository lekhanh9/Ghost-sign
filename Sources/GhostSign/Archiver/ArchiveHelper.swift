//
//  ArchiveHelper.swift
//  GhostSign
//
//  Handles IPA archive extraction, payload bundle resolution, and repackaging.
//

import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

public enum ArchiveHelperError: LocalizedError, Equatable {
    case fileNotFound(URL)
    case invalidIPAArchive(String)
    case missingPayloadDirectory(URL)
    case missingAppBundle(URL)
    case compressionFailed(String)

    public var errorDescription: String? {
        switch self {
        case .fileNotFound(let url):
            return "File not found at \(url.path)"
        case .invalidIPAArchive(let reason):
            return "Invalid IPA archive: \(reason)"
        case .missingPayloadDirectory(let url):
            return "Payload directory not found in unpacked archive at \(url.path)"
        case .missingAppBundle(let url):
            return "No .app bundle found inside Payload directory at \(url.path)"
        case .compressionFailed(let reason):
            return "Failed to repackage IPA: \(reason)"
        }
    }
}

public enum ArchiveHelper {

    /// Checks if a given URL points to an IPA archive.
    public static func isIPA(url: URL) -> Bool {
        let ext = url.pathExtension.lowercased()
        return ext == "ipa" || ext == "zip"
    }

    /// Checks if a given URL points to an uncompressed .app bundle directory.
    public static func isAppBundle(url: URL) -> Bool {
        url.pathExtension.lowercased() == "app"
    }

    /// Unpacks an IPA archive to a working directory and resolves the inner .app bundle URL.
    public static func unpack(ipaURL: URL, to workingDirectory: URL) throws -> URL {
        let fm = FileManager.default
        guard fm.fileExists(atPath: ipaURL.path) else {
            throw ArchiveHelperError.fileNotFound(ipaURL)
        }

        try fm.createDirectory(at: workingDirectory, withIntermediateDirectories: true)

        #if os(macOS) || os(Linux) || targetEnvironment(simulator)
        // Execute system unzip utility
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/unzip")
        process.arguments = ["-q", "-o", ipaURL.path, "-d", workingDirectory.path]
        try process.run()
        process.waitUntilExit()

        if process.terminationStatus != 0 {
            // Try fallback command if /usr/bin/unzip failed
            let fallback = Process()
            fallback.executableURL = URL(fileURLWithPath: "/bin/sh")
            fallback.arguments = ["-c", "unzip -q -o '\(ipaURL.path)' -d '\(workingDirectory.path)'"]
            try fallback.run()
            fallback.waitUntilExit()

            if fallback.terminationStatus != 0 {
                throw ArchiveHelperError.invalidIPAArchive("unzip terminated with status \(fallback.terminationStatus)")
            }
        }
        #else
        // On iOS (jailbreak environment), attempt /var/jb/usr/bin/unzip or /usr/bin/unzip
        let possibleUnzipPaths = ["/var/jb/usr/bin/unzip", "/usr/bin/unzip"]
        var extracted = false
        for unzipPath in possibleUnzipPaths {
            if fm.isExecutableFile(atPath: unzipPath) {
                let pid = fork()
                if pid == 0 {
                    let cUnzip = unzipPath.cString(using: .utf8)!
                    let cArg1 = "-q".cString(using: .utf8)!
                    let cArg2 = "-o".cString(using: .utf8)!
                    let cSrc = ipaURL.path.cString(using: .utf8)!
                    let cArg3 = "-d".cString(using: .utf8)!
                    let cDst = workingDirectory.path.cString(using: .utf8)!
                    var args: [UnsafeMutablePointer<CChar>?] = [
                        strdup(cUnzip), strdup(cArg1), strdup(cArg2), strdup(cSrc), strdup(cArg3), strdup(cDst), nil
                    ]
                    execv(cUnzip, &args)
                    exit(1)
                } else if pid > 0 {
                    var status: Int32 = 0
                    waitpid(pid, &status, 0)
                    if status == 0 {
                        extracted = true
                        break
                    }
                }
            }
        }
        if !extracted {
            throw ArchiveHelperError.invalidIPAArchive("No usable unzip utility found on device")
        }
        #endif

        let payloadURL = workingDirectory.appendingPathComponent("Payload")
        guard fm.fileExists(atPath: payloadURL.path) else {
            throw ArchiveHelperError.missingPayloadDirectory(workingDirectory)
        }

        let payloadContents = try fm.contentsOfDirectory(atPath: payloadURL.path)
        guard let appName = payloadContents.first(where: { $0.lowercased().hasSuffix(".app") }) else {
            throw ArchiveHelperError.missingAppBundle(payloadURL)
        }

        return payloadURL.appendingPathComponent(appName)
    }

    /// Packages an application bundle into a signed .ipa archive.
    public static func repack(appURL: URL, to ipaURL: URL) throws {
        let fm = FileManager.default
        let stagingDir = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let payloadDir = stagingDir.appendingPathComponent("Payload")
        try fm.createDirectory(at: payloadDir, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: stagingDir) }

        let stagedAppURL = payloadDir.appendingPathComponent(appURL.lastPathComponent)
        try fm.copyItem(at: appURL, to: stagedAppURL)

        if fm.fileExists(atPath: ipaURL.path) {
            try? fm.removeItem(at: ipaURL)
        }

        let ipaParent = ipaURL.deletingLastPathComponent()
        if !fm.fileExists(atPath: ipaParent.path) {
            try fm.createDirectory(at: ipaParent, withIntermediateDirectories: true)
        }

        #if os(macOS) || os(Linux) || targetEnvironment(simulator)
        let process = Process()
        process.currentDirectoryURL = stagingDir
        process.executableURL = URL(fileURLWithPath: "/usr/bin/zip")
        process.arguments = ["-qr", ipaURL.path, "Payload"]
        try process.run()
        process.waitUntilExit()

        if process.terminationStatus != 0 {
            let fallback = Process()
            fallback.currentDirectoryURL = stagingDir
            fallback.executableURL = URL(fileURLWithPath: "/bin/sh")
            fallback.arguments = ["-c", "zip -qr '\(ipaURL.path)' Payload"]
            try fallback.run()
            fallback.waitUntilExit()

            if fallback.terminationStatus != 0 {
                throw ArchiveHelperError.compressionFailed("zip terminated with exit status \(fallback.terminationStatus)")
            }
        }
        #else
        let possibleZipPaths = ["/var/jb/usr/bin/zip", "/usr/bin/zip"]
        var zipped = false
        for zipPath in possibleZipPaths {
            if fm.isExecutableFile(atPath: zipPath) {
                let pid = fork()
                if pid == 0 {
                    chdir(stagingDir.path)
                    let cZip = zipPath.cString(using: .utf8)!
                    let cArg1 = "-qr".cString(using: .utf8)!
                    let cDest = ipaURL.path.cString(using: .utf8)!
                    let cPayload = "Payload".cString(using: .utf8)!
                    var args: [UnsafeMutablePointer<CChar>?] = [
                        strdup(cZip), strdup(cArg1), strdup(cDest), strdup(cPayload), nil
                    ]
                    execv(cZip, &args)
                    exit(1)
                } else if pid > 0 {
                    var status: Int32 = 0
                    waitpid(pid, &status, 0)
                    if status == 0 {
                        zipped = true
                        break
                    }
                }
            }
        }
        if !zipped {
            throw ArchiveHelperError.compressionFailed("No usable zip utility found on device")
        }
        #endif
    }
}
