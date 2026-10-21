//
//  AnisetteDataProvider.swift
//  GhostSign
//
//  Created for Ghost-Sign.
//

import Foundation

/// Protocol defining the mechanism to fetch fresh Anisette attestation data.
public protocol AnisetteDataProvider: Sendable {
    func fetchAnisetteData() async throws -> AnisetteData
}

/// In-memory mock Anisette data provider for testing and offline development.
public struct MockAnisetteDataProvider: AnisetteDataProvider {
    public let data: AnisetteData

    public init(data: AnisetteData = AnisetteData()) {
        self.data = data
    }

    public func fetchAnisetteData() async throws -> AnisetteData {
        return data
    }
}
