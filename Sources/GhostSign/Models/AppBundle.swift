//
//  AppBundle.swift
//  GhostSign
//
//  Represents an iOS Application or App Extension bundle directory.
//  Discovers Info.plist, executables, nested app extensions (.appex), frameworks,
//  and extracts embedded code signing entitlements directly from Mach-O SuperBlobs.
//

import Foundation
import GhostCode

public struct AppBundle: Sendable, Identifiable, Hashable, Equatable {
    public var id: String { bundleIdentifier }

    public let name: String
    public let bundleIdentifier: String
    public let version: String
    public let buildVersion: String
    public let fileURL: URL
    public let executableURL: URL?
    public let executableName: String?
    public let infoPlistURL: URL
    public let infoPlist: [String: Any]
    public let isExtension: Bool
    public let provisioningProfile: ProvisioningProfile?

    public var appExtensions: [AppBundle] {
        loadExtensions()
    }

    public var frameworks: [URL] {
        loadFrameworks()
    }

    public var dylibs: [URL] {
        loadDylibs()
    }

    public var embeddedProvisioningProfileURL: URL {
        fileURL.appendingPathComponent("embedded.mobileprovision")
    }

    public init?(fileURL: URL) {
        let fm = FileManager.default
        guard fm.fileExists(atPath: fileURL.path) else { return nil }

        let plistURL = fileURL.appendingPathComponent("Info.plist")
        guard fm.fileExists(atPath: plistURL.path),
              let plistData = try? Data(contentsOf: plistURL),
              let rawPlist = (try? PropertyListSerialization.propertyList(from: plistData, options: [], format: nil)) as? [String: Any] else {
            return nil
        }

        let bundleID = (rawPlist["CFBundleIdentifier"] as? String)
            ?? (rawPlist["bundle-identifier"] as? String)
            ?? fileURL.deletingPathExtension().lastPathComponent

        let displayName = (rawPlist["CFBundleDisplayName"] as? String)
            ?? (rawPlist["CFBundleName"] as? String)
            ?? fileURL.deletingPathExtension().lastPathComponent

        let version = (rawPlist["CFBundleShortVersionString"] as? String) ?? "1.0"
        let buildVersion = (rawPlist["CFBundleVersion"] as? String) ?? "1"
        let exeName = (rawPlist["CFBundleExecutable"] as? String)

        var resolvedExeURL: URL?
        if let exeName = exeName {
            let candidate = fileURL.appendingPathComponent(exeName)
            if fm.fileExists(atPath: candidate.path) {
                resolvedExeURL = candidate
            }
        }
        if resolvedExeURL == nil {
            let fallbackName = fileURL.deletingPathExtension().lastPathComponent
            let candidate = fileURL.appendingPathComponent(fallbackName)
            if fm.fileExists(atPath: candidate.path) {
                resolvedExeURL = candidate
            }
        }

        let profileURL = fileURL.appendingPathComponent("embedded.mobileprovision")
        let profile = try? ProvisioningProfile(url: profileURL)

        self.name = displayName
        self.bundleIdentifier = bundleID
        self.version = version
        self.buildVersion = buildVersion
        self.fileURL = fileURL
        self.executableURL = resolvedExeURL
        self.executableName = exeName ?? resolvedExeURL?.lastPathComponent
        self.infoPlistURL = plistURL
        self.infoPlist = rawPlist
        self.isExtension = fileURL.pathExtension.lowercased() == "appex"
        self.provisioningProfile = profile
    }

    public static func == (lhs: AppBundle, rhs: AppBundle) -> Bool {
        lhs.bundleIdentifier == rhs.bundleIdentifier && lhs.fileURL == rhs.fileURL
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(bundleIdentifier)
        hasher.combine(fileURL.path)
    }

    // MARK: - Subcomponents Discovery

    private func loadExtensions() -> [AppBundle] {
        let pluginsURL = fileURL.appendingPathComponent("PlugIns")
        guard let items = try? FileManager.default.contentsOfDirectory(at: pluginsURL, includingPropertiesForKeys: nil) else {
            return []
        }
        return items
            .filter { $0.pathExtension.lowercased() == "appex" }
            .compactMap { AppBundle(fileURL: $0) }
    }

    private func loadFrameworks() -> [URL] {
        let frameworksURL = fileURL.appendingPathComponent("Frameworks")
        guard let items = try? FileManager.default.contentsOfDirectory(at: frameworksURL, includingPropertiesForKeys: nil) else {
            return []
        }
        return items.filter { $0.pathExtension.lowercased() == "framework" }
    }

    private func loadDylibs() -> [URL] {
        let frameworksURL = fileURL.appendingPathComponent("Frameworks")
        guard let items = try? FileManager.default.contentsOfDirectory(at: frameworksURL, includingPropertiesForKeys: nil) else {
            return []
        }
        return items.filter { $0.pathExtension.lowercased() == "dylib" }
    }

    // MARK: - Mach-O Embedded Entitlements Extraction

    /// Extracts original XML entitlements from the Mach-O binary's embedded LC_CODE_SIGNATURE SuperBlob.
    /// Falls back to embedded.mobileprovision entitlements if not found in the binary.
    public func extractEmbeddedEntitlements() -> [String: Any]? {
        guard let exeURL = executableURL,
              let binaryData = try? Data(contentsOf: exeURL) else {
            return provisioningProfile?.entitlements
        }

        if let ents = Self.extractEntitlements(fromMachOData: binaryData) {
            return ents
        }

        return provisioningProfile?.entitlements
    }

    /// Extracts embedded XML entitlements from raw Mach-O binary bytes (handles single-arch 64-bit and FAT universal).
    public static func extractEntitlements(fromMachOData data: Data) -> [String: Any]? {
        guard data.count >= 32 else { return nil }

        let magic = data.withUnsafeBytes { raw in
            UInt32(bigEndian: raw.loadUnaligned(fromByteOffset: 0, as: UInt32.self))
        }

        // FAT Universal Binary (0xcafebabe or 0xbebafeca)
        if magic == 0xcafebabe || magic == 0xbebafeca {
            let isBigEndian = (magic == 0xcafebabe)
            let nfat_arch = data.withUnsafeBytes { raw -> UInt32 in
                let val = raw.loadUnaligned(fromByteOffset: 4, as: UInt32.self)
                return isBigEndian ? UInt32(bigEndian: val) : UInt32(littleEndian: val)
            }
            var arm64Offset: Int?
            var arm64Size: Int?
            var offset = 8
            for _ in 0..<min(Int(nfat_arch), 16) {
                guard offset + 20 <= data.count else { break }
                let cputype = data.withUnsafeBytes { raw -> UInt32 in
                    let val = raw.loadUnaligned(fromByteOffset: offset, as: UInt32.self)
                    return isBigEndian ? UInt32(bigEndian: val) : UInt32(littleEndian: val)
                }
                let archOffset = data.withUnsafeBytes { raw -> UInt32 in
                    let val = raw.loadUnaligned(fromByteOffset: offset + 8, as: UInt32.self)
                    return isBigEndian ? UInt32(bigEndian: val) : UInt32(littleEndian: val)
                }
                let archSize = data.withUnsafeBytes { raw -> UInt32 in
                    let val = raw.loadUnaligned(fromByteOffset: offset + 12, as: UInt32.self)
                    return isBigEndian ? UInt32(bigEndian: val) : UInt32(littleEndian: val)
                }
                // CPU_TYPE_ARM64 = 0x0100000C
                if cputype == 0x0100000c {
                    arm64Offset = Int(archOffset)
                    arm64Size = Int(archSize)
                    break
                }
                offset += 20
            }
            if let aOff = arm64Offset, let aSize = arm64Size, aOff + aSize <= data.count {
                let sliceData = data.subdata(in: aOff..<(aOff + aSize))
                return extractEntitlementsFromSingleMachO(sliceData)
            }
        }

        return extractEntitlementsFromSingleMachO(data)
    }

    private static func extractEntitlementsFromSingleMachO(_ data: Data) -> [String: Any]? {
        guard data.count >= 32 else { return nil }

        let magic = data.withUnsafeBytes { raw in
            UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: 0, as: UInt32.self))
        }
        guard magic == MachOConstants.MH_MAGIC_64 else { return nil }

        let ncmds = data.withUnsafeBytes { raw in
            UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: 16, as: UInt32.self))
        }
        let sizeofcmds = data.withUnsafeBytes { raw in
            UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: 20, as: UInt32.self))
        }

        let maxOffset = min(data.count, 32 + Int(sizeofcmds))
        var offset = 32
        var codeSigOffset: Int?

        for _ in 0..<ncmds {
            guard offset + 8 <= maxOffset else { break }
            let cmd = data.withUnsafeBytes { raw in
                UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: offset, as: UInt32.self))
            }
            let cmdsize = data.withUnsafeBytes { raw in
                UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: offset + 4, as: UInt32.self))
            }
            guard cmdsize >= 8, offset + Int(cmdsize) <= maxOffset else { break }

            if cmd == MachOConstants.LC_CODE_SIGNATURE {
                guard cmdsize >= 16 else { break }
                let dataoff = data.withUnsafeBytes { raw in
                    UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: offset + 8, as: UInt32.self))
                }
                codeSigOffset = Int(dataoff)
                break
            }
            offset += Int(cmdsize)
        }

        guard let sigOff = codeSigOffset, sigOff + 12 <= data.count else { return nil }

        // Parse SuperBlob header
        let sbMagic = data.withUnsafeBytes { raw in
            UInt32(bigEndian: raw.loadUnaligned(fromByteOffset: sigOff, as: UInt32.self))
        }
        guard sbMagic == MachOConstants.CSMAGIC_EMBEDDED_SIGNATURE else { return nil }

        let count = data.withUnsafeBytes { raw in
            UInt32(bigEndian: raw.loadUnaligned(fromByteOffset: sigOff + 8, as: UInt32.self))
        }

        for i in 0..<Int(count) {
            let slotHeaderOffset = sigOff + 12 + i * 8
            guard slotHeaderOffset + 8 <= data.count else { break }

            let slotType = data.withUnsafeBytes { raw in
                UInt32(bigEndian: raw.loadUnaligned(fromByteOffset: slotHeaderOffset, as: UInt32.self))
            }
            let blobOffset = data.withUnsafeBytes { raw in
                UInt32(bigEndian: raw.loadUnaligned(fromByteOffset: slotHeaderOffset + 4, as: UInt32.self))
            }

            // CSSLOT_ENTITLEMENTS = 5
            if slotType == MachOConstants.CSSLOT_ENTITLEMENTS {
                let actualBlobOffset = sigOff + Int(blobOffset)
                guard actualBlobOffset + 8 <= data.count else { break }

                let blobMagic = data.withUnsafeBytes { raw in
                    UInt32(bigEndian: raw.loadUnaligned(fromByteOffset: actualBlobOffset, as: UInt32.self))
                }
                let blobLength = data.withUnsafeBytes { raw in
                    UInt32(bigEndian: raw.loadUnaligned(fromByteOffset: actualBlobOffset + 4, as: UInt32.self))
                }

                // CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171
                guard blobMagic == GhostCodeConstants.CodeSigning.CSMAGIC_EMBEDDED_ENTITLEMENTS,
                      blobLength >= 8,
                      actualBlobOffset + Int(blobLength) <= data.count else { break }

                let xmlData = data.subdata(in: (actualBlobOffset + 8)..<(actualBlobOffset + Int(blobLength)))
                if let plist = try? PropertyListSerialization.propertyList(from: xmlData, options: [], format: nil) as? [String: Any] {
                    return plist
                }
            }
        }

        return nil
    }
}
