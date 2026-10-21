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
        let blocks = extractPEMBlocks(pem: pem)
        if let first = blocks.first {
            return first.data
        }
        let lines = pem.components(separatedBy: .newlines)
        let filtered = lines.filter { line in
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            return !trimmed.isEmpty && !trimmed.hasPrefix("-----")
        }.joined()
        return Data(base64Encoded: filtered)
    }

    /// Extracts all distinct PEM blocks (type and raw binary DER data) from an ASCII PEM string.
    public static func extractPEMBlocks(pem: String) -> [(type: String, data: Data)] {
        var blocks: [(type: String, data: Data)] = []
        var currentType: String? = nil
        var currentBase64 = ""

        let lines = pem.components(separatedBy: .newlines)
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.hasPrefix("-----BEGIN ") && trimmed.hasSuffix("-----") {
                let start = trimmed.index(trimmed.startIndex, offsetBy: 11)
                let end = trimmed.index(trimmed.endIndex, offsetBy: -5)
                currentType = String(trimmed[start..<end])
                currentBase64 = ""
            } else if trimmed.hasPrefix("-----END ") && trimmed.hasSuffix("-----") {
                let start = trimmed.index(trimmed.startIndex, offsetBy: 9)
                let end = trimmed.index(trimmed.endIndex, offsetBy: -5)
                let endType = String(trimmed[start..<end])
                if let type = currentType, type == endType, let data = Data(base64Encoded: currentBase64) {
                    blocks.append((type: type, data: data))
                }
                currentType = nil
                currentBase64 = ""
            } else if currentType != nil {
                currentBase64.append(trimmed)
            }
        }
        return blocks
    }

    /// Parses a PEM-armored string that may contain both a Certificate and a Private Key.
    public static func parsePEMIdentity(pemString: String) -> RawIdentity? {
        let blocks = extractPEMBlocks(pem: pemString)
        var certData: Data? = nil
        var keyData: Data? = nil
        var certPEM: String? = nil
        var keyPEM: String? = nil

        for block in blocks {
            let upper = block.type.uppercased()
            if upper.contains("CERTIFICATE") && certData == nil {
                certData = block.data
                certPEM = derToPEM(der: block.data, type: block.type)
            } else if upper.contains("PRIVATE KEY") && keyData == nil {
                keyData = block.data
                keyPEM = derToPEM(der: block.data, type: block.type)
            }
        }

        guard let cert = certData, let key = keyData else { return nil }
        return RawIdentity(
            certificateDER: cert,
            privateKeyDER: key,
            certificatePEM: certPEM,
            privateKeyPEM: keyPEM
        )
    }
}
