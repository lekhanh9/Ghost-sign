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

/// Provider that contacts an external Anisette v3 server (e.g. dadoum/anisette-v3-server).
public struct RemoteAnisetteProvider: AnisetteDataProvider {
    public let serverURL: URL
    public let clientConfiguration: AppleClientConfiguration
    private let urlSession: URLSession

    public init(
        serverURL: URL,
        clientConfiguration: AppleClientConfiguration = .default,
        urlSession: URLSession = .shared
    ) {
        self.serverURL = serverURL
        self.clientConfiguration = clientConfiguration
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

        let anisette = AnisetteData(
            machineID: (json["X-Apple-I-MD-M"] as? String) ?? (json["machine_id"] as? String) ?? "",
            oneTimePassword: (json["X-Apple-I-MD"] as? String) ?? (json["otp"] as? String) ?? "",
            localUserID: (json["X-Apple-I-MD-LU"] as? String) ?? (json["local_user_id"] as? String) ?? "",
            routingInfo: (json["X-Apple-I-MD-RINFO"] as? String) ?? (json["routing_info"] as? String) ?? "17106176",
            deviceID: (json["X-Mme-Device-Id"] as? String) ?? (json["device_id"] as? String) ?? UUID().uuidString,
            serialNumber: (json["X-Apple-I-SRL-NO"] as? String) ?? (json["serial_number"] as? String) ?? "",
            clientInfo: (json["X-MMe-Client-Info"] as? String) ?? (json["client_info"] as? String) ?? AppleClientConfiguration.defaultClientInfo,
            userAgent: AppleClientConfiguration.defaultUserAgent,
            clientTime: (json["X-Apple-I-Client-Time"] as? String) ?? ISO8601DateFormatter().string(from: Date()),
            locale: (json["X-Apple-Locale"] as? String) ?? Locale.current.identifier,
            timeZone: (json["X-Apple-I-TimeZone"] as? String) ?? (TimeZone.current.abbreviation() ?? "UTC")
        )
        return clientConfiguration.applying(to: anisette)
    }
}
