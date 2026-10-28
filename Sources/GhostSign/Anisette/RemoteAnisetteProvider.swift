//
//  RemoteAnisetteProvider.swift
//  GhostSign
//
//  Created for Ghost-Sign.
//

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public enum AnisetteError: LocalizedError {
    case invalidServerURL
    case badServerResponse(statusCode: Int, message: String)
    case missingHeader(String)

    public var errorDescription: String? {
        switch self {
        case .invalidServerURL:
            return "Invalid Anisette server URL."
        case .badServerResponse(let statusCode, let message):
            return "Anisette server error (HTTP \(statusCode)): \(message)"
        case .missingHeader(let header):
            return "Missing expected Anisette header: \(header)"
        }
    }
}

/// Provider that contacts an external Anisette v3 server (e.g. ani.sidestore.io).
/// Every client identity header (client info, user agent) is taken verbatim
/// from the server response; nothing is hardcoded or overridden locally.
public struct RemoteAnisetteProvider: AnisetteDataProvider {
    public let serverURL: URL
    private let urlSession: URLSession

    public static var defaultURL: URL {
        URL(string: Constants.Anisette.defaultServerURL) ?? URL(string: "https://ani.sidestore.io")!
    }

    public init(
        serverURL: URL = RemoteAnisetteProvider.defaultURL,
        urlSession: URLSession = .shared
    ) {
        self.serverURL = serverURL
        self.urlSession = urlSession
    }

    public func fetchAnisetteData() async throws -> AnisetteData {
        var request = URLRequest(url: serverURL)
        request.httpMethod = "GET"
        request.timeoutInterval = 15

        let (data, response) = try await urlSession.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse, (200...299).contains(httpResponse.statusCode) else {
            let code = (response as? HTTPURLResponse)?.statusCode ?? -1
            let msg = String(data: data, encoding: .utf8) ?? "Unknown server response"
            throw AnisetteError.badServerResponse(statusCode: code, message: "\(msg) — \(serverURL.absoluteString)")
        }

        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw AnisetteError.badServerResponse(statusCode: httpResponse.statusCode, message: "Response is not valid JSON — \(serverURL.absoluteString)")
        }

        // Anisette servers disagree on header casing, so match case-insensitively.
        func header(_ keys: String...) -> String? {
            for key in keys {
                if let name = json.keys.first(where: { $0.caseInsensitiveCompare(key) == .orderedSame }),
                   let value = json[name] as? String,
                   !value.isEmpty {
                    return value
                }
            }
            return nil
        }

        guard let clientInfo = header("X-MMe-Client-Info", "client_info") else {
            throw AnisetteError.missingHeader("X-MMe-Client-Info — the Anisette server at \(serverURL.absoluteString) did not report a client identity")
        }

        return AnisetteData(
            machineID: header("X-Apple-I-MD-M", "machine_id") ?? "",
            oneTimePassword: header("X-Apple-I-MD", "otp") ?? "",
            localUserID: header("X-Apple-I-MD-LU", "local_user_id") ?? "",
            routingInfo: header("X-Apple-I-MD-RINFO", "routing_info") ?? "17106176",
            deviceID: header("X-Mme-Device-Id", "device_id") ?? UUID().uuidString,
            serialNumber: header("X-Apple-I-SRL-NO", "serial_number") ?? "",
            clientInfo: clientInfo,
            userAgent: header("User-Agent", "user_agent") ?? "",
            clientTime: header("X-Apple-I-Client-Time", "client_time") ?? ISO8601DateFormatter().string(from: Date()),
            locale: header("X-Apple-Locale", "locale") ?? Locale.current.identifier,
            timeZone: header("X-Apple-I-TimeZone", "time_zone") ?? (TimeZone.current.abbreviation() ?? "UTC")
        )
    }
}
