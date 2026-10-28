//
//  AnisetteData.swift
//  GhostSign
//
//  Created for Ghost-Sign.
//

import Foundation

/// Encapsulates Apple Anisette device attestation headers required for GrandSlam and Developer Services.
public struct AnisetteData: Sendable, Codable, Equatable, Hashable {
    public var machineID: String
    public var oneTimePassword: String
    public var localUserID: String
    public var routingInfo: String
    public var deviceID: String
    public var serialNumber: String
    public var clientInfo: String
    public var userAgent: String
    public var clientTime: String
    public var locale: String
    public var timeZone: String

    public init(
        machineID: String = "",
        oneTimePassword: String = "",
        localUserID: String = "",
        routingInfo: String = "17106176",
        deviceID: String = UUID().uuidString,
        serialNumber: String = "",
        clientInfo: String = "",
        userAgent: String = "",
        clientTime: String = ISO8601DateFormatter().string(from: Date()),
        locale: String = Locale.current.identifier,
        timeZone: String = TimeZone.current.abbreviation() ?? "UTC"
    ) {
        self.machineID = machineID
        self.oneTimePassword = oneTimePassword
        self.localUserID = localUserID
        self.routingInfo = routingInfo
        self.deviceID = deviceID
        self.serialNumber = serialNumber
        self.clientInfo = clientInfo
        self.userAgent = userAgent
        self.clientTime = clientTime
        self.locale = locale
        self.timeZone = timeZone
    }

    /// Converts the attestation fields into standard Apple HTTP header pairs with refreshed client time.
    public func toHTTPHeaders(refreshTimestamp: Bool = true) -> [String: String] {
        let effectiveTime = refreshTimestamp ? ISO8601DateFormatter().string(from: Date()) : clientTime

        var headers: [String: String] = [
            "X-Apple-I-MD": oneTimePassword,
            "X-Apple-I-MD-M": machineID,
            "X-Apple-I-MD-LU": localUserID,
            "X-Apple-I-MD-RINFO": routingInfo.isEmpty ? Constants.Anisette.defaultRoutingInfo : routingInfo,
            "X-Mme-Device-Id": deviceID,
            "X-Apple-I-Client-Time": effectiveTime,
            "X-Apple-Locale": locale.isEmpty ? Locale.current.identifier : locale,
            "X-Apple-I-TimeZone": timeZone.isEmpty ? (TimeZone.current.abbreviation() ?? "UTC") : timeZone
        ]
        if !serialNumber.isEmpty {
            headers["X-Apple-I-SRL-NO"] = serialNumber
        }
        if !clientInfo.isEmpty {
            headers["X-MMe-Client-Info"] = clientInfo
            headers["X-Apple-I-Client-Info"] = clientInfo
        }
        if !userAgent.isEmpty {
            headers["User-Agent"] = userAgent
        }
        return headers
    }
}
