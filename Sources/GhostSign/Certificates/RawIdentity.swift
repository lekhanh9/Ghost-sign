//
//  RawIdentity.swift
//  GhostSign
//
//  Represents an in-memory X.509 Certificate and Private Key (Raw Crypto).
//  STRICT ARCHITECTURE DIRECTIVE: Never saved to Apple Keychain.
//

import Foundation

public struct RawIdentity: Sendable, Equatable {
    /// Raw binary ASN.1 DER-encoded X.509 certificate data.
    public let certificateDER: Data

    /// Raw binary ASN.1 DER-encoded RSA/ECC private key data (PKCS#1 or PKCS#8).
    public let privateKeyDER: Data

    /// Optional ASCII PEM-armored certificate string.
    public let certificatePEM: String?

    /// Optional ASCII PEM-armored private key string.
    public let privateKeyPEM: String?

    public init(
        certificateDER: Data,
        privateKeyDER: Data,
        certificatePEM: String? = nil,
        privateKeyPEM: String? = nil
    ) {
        self.certificateDER = certificateDER
        self.privateKeyDER = privateKeyDER
        self.certificatePEM = certificatePEM
        self.privateKeyPEM = privateKeyPEM
    }

    /// Converts raw DER data to standard PEM armored ASCII string.
    public static func derToPEM(der: Data, type: String) -> String {
        let base64 = der.base64EncodedString()
        var pem = "-----BEGIN \(type)-----\n"
        var index = base64.startIndex
        while index < base64.endIndex {
            let nextIndex = base64.index(index, offsetBy: 64, limitedBy: base64.endIndex) ?? base64.endIndex
            pem.append(String(base64[index..<nextIndex]) + "\n")
            index = nextIndex
        }
        pem.append("-----END \(type)-----")
        return pem
    }

    /// Extracts binary DER data from a PEM-armored ASCII string.
    public static func pemToDER(pem: String) -> Data? {
        let lines = pem.components(separatedBy: .newlines)
        let filtered = lines.filter { line in
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            return !trimmed.isEmpty && !trimmed.hasPrefix("-----")
        }.joined()
        return Data(base64Encoded: filtered)
    }
}
