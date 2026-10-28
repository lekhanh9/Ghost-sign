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
        return ensureAuthKitLoaded()
    }

    @discardableResult
    private static func ensureAuthKitLoaded() -> Bool {
        if NSClassFromString("AKAppleIDSession") != nil || NSClassFromString("AKAnisetteProvisioningController") != nil {
            return true
        }

        // Dyld Shared Cache note:
        // On iOS 14+, macOS 11+, and modern rootless jailbreaks (iOS 15/16/17 Dopamine/Cryptex),
        // Apple does NOT store framework Mach-O binaries as physical files on disk.
        // Calling `FileManager.default.fileExists(atPath:)` returns FALSE!
        // Instead, dyld resolves paths directly from the in-memory shared cache map.
        // Therefore, we call dlopen() directly on the system framework paths.
        let candidatePaths = [
            "/System/Library/PrivateFrameworks/AuthKit.framework/AuthKit",
            "/System/Library/Frameworks/AuthKit.framework/AuthKit"
        ]

        for path in candidatePaths {
            if dlopen(path, RTLD_NOW | RTLD_GLOBAL) != nil {
                break
            }
        }

        return NSClassFromString("AKAppleIDSession") != nil || NSClassFromString("AKAnisetteProvisioningController") != nil
    }

    public func fetchAnisetteData() async throws -> AnisetteData {
        guard Self.ensureAuthKitLoaded() else {
            throw AnisetteError.badServerResponse(
                statusCode: -1,
                message: "Native Apple AuthKit framework is not available on this platform."
            )
        }

        var headers: [String: String] = [:]

        // 1. Primary method: Query genuine headers via AKAppleIDSession (XPC client to akd daemon)
        if let sessionClass = NSClassFromString("AKAppleIDSession") as? NSObject.Type {
            let allocSelector = NSSelectorFromString("alloc")
            let initSelector = NSSelectorFromString("initWithIdentifier:")
            let headersSelector = NSSelectorFromString("appleIDHeadersForRequest:")

            if let allocated = sessionClass.perform(allocSelector)?.takeUnretainedValue(),
               let sessionInstance = allocated.perform(initSelector, with: "com.apple.gs.xcode.auth")?.takeUnretainedValue(),
               let rawHeaders = sessionInstance.perform(headersSelector, with: nil)?.takeUnretainedValue() as? [String: String] {
                headers = rawHeaders
            }
        }

        var otp = headers["X-Apple-I-MD"] ?? ""
        var machineID = headers["X-Apple-I-MD-M"] ?? ""
        var routingInfo = headers["X-Apple-I-MD-RINFO"] ?? ""
        var localUserID = headers["X-Apple-I-MD-LU"] ?? ""
        var deviceID = headers["X-Mme-Device-Id"] ?? ""
        var serialNumber = headers["X-Apple-I-SRL-NO"] ?? ""
        var clientInfo = headers["X-MMe-Client-Info"] ?? headers["X-Apple-I-Client-Info"] ?? ""

        // 2. Secondary method: If AKAppleIDSession returned empty headers (e.g. initial launch),
        // query AKAnisetteProvisioningController directly.
        if otp.isEmpty || machineID.isEmpty {
            if let controllerClass = NSClassFromString("AKAnisetteProvisioningController") as? NSObject.Type {
                let sharedSelector = NSSelectorFromString("sharedController")
                let allocSelector = NSSelectorFromString("alloc")
                let initSelector = NSSelectorFromString("init")

                let controllerInstance: AnyObject?
                if controllerClass.responds(to: sharedSelector) {
                    controllerInstance = controllerClass.perform(sharedSelector)?.takeUnretainedValue()
                } else if let allocated = controllerClass.perform(allocSelector)?.takeUnretainedValue() {
                    controllerInstance = allocated.perform(initSelector)?.takeUnretainedValue()
                } else {
                    controllerInstance = nil
                }

                if let controller = controllerInstance {
                    let anisetteDataSelector = NSSelectorFromString("anisetteDataWithError:")
                    if controller.responds(to: anisetteDataSelector) {
                        if let dataObj = controller.perform(anisetteDataSelector, with: nil)?.takeUnretainedValue() {
                            let midSel = NSSelectorFromString("machineID")
                            let otpSel = NSSelectorFromString("oneTimePassword")
                            let rinfoSel = NSSelectorFromString("routingInfo")

                            if machineID.isEmpty && dataObj.responds(to: midSel),
                               let mid = dataObj.perform(midSel)?.takeUnretainedValue() as? String {
                                machineID = mid
                            }
                            if otp.isEmpty && dataObj.responds(to: otpSel),
                               let p = dataObj.perform(otpSel)?.takeUnretainedValue() as? String {
                                otp = p
                            }
                            if routingInfo.isEmpty && dataObj.responds(to: rinfoSel),
                               let r = dataObj.perform(rinfoSel)?.takeUnretainedValue() {
                                routingInfo = "\(r)"
                            }
                        }
                    }
                }
            }
        }

        // 3. Hardware identifiers via AKDevice
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

        // Validate that we obtained actual cryptographic attestation from the akd daemon.
        // If empty (e.g. sandbox blocked XPC connection to akd daemon without com.apple.authkit.client.private entitlement),
        // throw so SmartAnisetteProvider cleanly falls back to RemoteAnisetteProvider.
        guard !otp.isEmpty || !machineID.isEmpty else {
            throw AnisetteError.badServerResponse(
                statusCode: -1,
                message: "AuthKit (akd daemon) did not return Anisette tokens. Verify 'com.apple.authkit.client.private' entitlement is present."
            )
        }

        if deviceID.isEmpty {
            deviceID = UUID().uuidString
        }

        let dateFormatter = ISO8601DateFormatter()
        let now = Date()

        return AnisetteData(
            machineID: machineID,
            oneTimePassword: otp,
            localUserID: localUserID,
            routingInfo: routingInfo.isEmpty ? Constants.Anisette.defaultRoutingInfo : routingInfo,
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
