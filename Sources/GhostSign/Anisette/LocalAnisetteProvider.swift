//
//  LocalAnisetteProvider.swift
//  GhostSign
//
//  Provides native, on-device Apple Anisette attestation without external servers.
//  Dynamically accesses Apple's private AuthKit framework (AKAppleIDSession & AKDevice)
//  on iOS and macOS to generate genuine, zero-latency attestation headers offline.
//

import Foundation

#if canImport(ObjectiveC) && canImport(Darwin)
import ObjectiveC
import Darwin

public struct LocalAnisetteProvider: AnisetteDataProvider, Sendable {

    public init() {}

    /// Checks if Apple's native AuthKit framework and AKAppleIDSession are available.
    public static var isAvailable: Bool {
        ensureAuthKitLoaded()
        return NSClassFromString("AKAppleIDSession") != nil
    }

    private static func ensureAuthKitLoaded() {
        let authKitPath = "/System/Library/PrivateFrameworks/AuthKit.framework/AuthKit"
        if FileManager.default.fileExists(atPath: authKitPath) {
            _ = dlopen(authKitPath, RTLD_NOW)
        }
    }

    public func fetchAnisetteData() async throws -> AnisetteData {
        Self.ensureAuthKitLoaded()

        guard let sessionClass = NSClassFromString("AKAppleIDSession") as? NSObject.Type else {
            throw AnisetteError.badServerResponse(
                statusCode: -1,
                message: "Native Apple AuthKit framework (AKAppleIDSession) is not available on this platform."
            )
        }

        // Allocate and initialize AKAppleIDSession with "com.apple.gs.xcode.auth"
        let allocSelector = NSSelectorFromString("alloc")
        guard let allocated = sessionClass.perform(allocSelector)?.takeUnretainedValue() else {
            throw AnisetteError.badServerResponse(statusCode: -1, message: "Failed to allocate AKAppleIDSession.")
        }

        let initSelector = NSSelectorFromString("initWithIdentifier:")
        guard let sessionInstance = allocated.perform(initSelector, with: "com.apple.gs.xcode.auth")?.takeUnretainedValue() else {
            throw AnisetteError.badServerResponse(statusCode: -1, message: "Failed to initialize AKAppleIDSession.")
        }

        // Query genuine on-device Apple ID headers
        let headersSelector = NSSelectorFromString("appleIDHeadersForRequest:")
        guard let headers = sessionInstance.perform(headersSelector, with: nil)?.takeUnretainedValue() as? [String: String] else {
            throw AnisetteError.badServerResponse(statusCode: -1, message: "AKAppleIDSession failed to generate Apple ID headers.")
        }

        var deviceID = headers["X-Mme-Device-Id"] ?? ""
        var serialNumber = headers["X-Apple-I-SRL-NO"] ?? ""
        var clientInfo = headers["X-MMe-Client-Info"] ?? headers["X-Apple-I-Client-Info"] ?? ""

        // Query AKDevice for hardware-specific identifiers
        if let deviceClass = NSClassFromString("AKDevice") as? NSObject.Type {
            let currentDevSelector = NSSelectorFromString("currentDevice")
            if let currentDevice = deviceClass.perform(currentDevSelector)?.takeUnretainedValue() {
                if deviceID.isEmpty {
                    let udidSelector = NSSelectorFromString("uniqueDeviceIdentifier")
                    if currentDevice.responds(to: udidSelector),
                       let udid = currentDevice.perform(udidSelector)?.takeUnretainedValue() as? String {
                        deviceID = udid
                    }
                }
                if serialNumber.isEmpty {
                    let serialSelector = NSSelectorFromString("serialNumber")
                    if currentDevice.responds(to: serialSelector),
                       let srl = currentDevice.perform(serialSelector)?.takeUnretainedValue() as? String {
                        serialNumber = srl
                    }
                }
                if clientInfo.isEmpty {
                    let descSelector = NSSelectorFromString("serverFriendlyDescription")
                    if currentDevice.responds(to: descSelector),
                       let desc = currentDevice.perform(descSelector)?.takeUnretainedValue() as? String {
                        clientInfo = desc
                    }
                }
            }
        }

        if deviceID.isEmpty {
            deviceID = UUID().uuidString
        }

        let dateFormatter = ISO8601DateFormatter()
        let now = Date()

        return AnisetteData(
            machineID: headers["X-Apple-I-MD-M"] ?? "",
            oneTimePassword: headers["X-Apple-I-MD"] ?? "",
            localUserID: headers["X-Apple-I-MD-LU"] ?? "",
            routingInfo: headers["X-Apple-I-MD-RINFO"] ?? Constants.Anisette.defaultRoutingInfo,
            deviceID: deviceID,
            serialNumber: serialNumber,
            clientInfo: clientInfo.isEmpty ? "<iPhone;iOS;16.0> <com.apple.AuthKit/1 (com.apple.akd/1.0)>" : clientInfo,
            userAgent: "akd/1.0 CFNetwork Darwin",
            clientTime: dateFormatter.string(from: now),
            locale: Locale.current.identifier,
            timeZone: TimeZone.current.abbreviation() ?? "UTC"
        )
    }
}
#else
public struct LocalAnisetteProvider: AnisetteDataProvider, Sendable {
    public init() {}
    public static var isAvailable: Bool { false }

    public func fetchAnisetteData() async throws -> AnisetteData {
        throw AnisetteError.badServerResponse(
            statusCode: -1,
            message: "Local AuthKit Anisette is only available on Apple platforms (iOS/macOS)."
        )
    }
}
#endif

/// Intelligent hybrid Anisette provider:
/// Automatically uses native on-device `LocalAnisetteProvider` (offline & zero server) when available on iOS/macOS,
/// and falls back seamlessly to `RemoteAnisetteProvider` on Linux or when AuthKit is unavailable.
public struct SmartAnisetteProvider: AnisetteDataProvider, Sendable {
    public let remoteProvider: RemoteAnisetteProvider
    public let localProvider: LocalAnisetteProvider
    public let preferLocal: Bool

    public init(
        remoteServerURL: URL = RemoteAnisetteProvider.defaultURL,
        preferLocal: Bool = true
    ) {
        self.remoteProvider = RemoteAnisetteProvider(serverURL: remoteServerURL)
        self.localProvider = LocalAnisetteProvider()
        self.preferLocal = preferLocal
    }

    public func fetchAnisetteData() async throws -> AnisetteData {
        if preferLocal && LocalAnisetteProvider.isAvailable {
            do {
                return try await localProvider.fetchAnisetteData()
            } catch {
                return try await remoteProvider.fetchAnisetteData()
            }
        }
        return try await remoteProvider.fetchAnisetteData()
    }
}
