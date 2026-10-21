//
//  PEMDERCodec.swift
//  GhostSign
//
//  Created for Ghost-Sign.
//  Universal codec for bi-directional conversion between binary DER and ASCII-armored PEM formats.
//  Supports Private Keys, Public Keys, X.509 Certificates, and PKCS#10 CSRs.
//

import Foundation

public enum CryptoItemType: String, Sendable, CaseIterable {
    case certificate           = "CERTIFICATE"
    case rsaPrivateKey         = "RSA PRIVATE KEY"
    case privateKey            = "PRIVATE KEY"
    case publicKey             = "PUBLIC KEY"
    case rsaPublicKey          = "RSA PUBLIC KEY"
    case certificateRequest    = "CERTIFICATE REQUEST"
    case newCertificateRequest = "NEW CERTIFICATE REQUEST"
}

public enum PEMDERCodec {

    /// Detects whether data begins with ASCII "-----BEGIN ".
    public static func isPEM(_ data: Data) -> Bool {
        guard data.count >= 11 else { return false }
        let prefix = String(decoding: data.prefix(11), as: UTF8.self)
        return prefix.hasPrefix("-----BEGIN ")
    }

    /// Converts raw DER data to standard PEM-armored ASCII string with the given type header.
    public static func derToPEM(der: Data, type: CryptoItemType) -> String {
        return derToPEM(der: der, label: type.rawValue)
    }

    /// Converts raw DER data to PEM string with arbitrary label.
    public static func derToPEM(der: Data, label: String) -> String {
        let base64 = der.base64EncodedString()
        var pem = "-----BEGIN \(label)-----\n"
        var index = base64.startIndex
        while index < base64.endIndex {
            let nextIndex = base64.index(index, offsetBy: 64, limitedBy: base64.endIndex) ?? base64.endIndex
            pem.append(String(base64[index..<nextIndex]) + "\n")
            index = nextIndex
        }
        pem.append("-----END \(label)-----\n")
        return pem
    }

    /// Extracts binary DER data from a PEM-armored ASCII string.
    public static func pemToDER(_ pem: String, expectedType: CryptoItemType? = nil) -> Data? {
        let blocks = RawIdentity.extractPEMBlocks(pem: pem)
        if let expected = expectedType {
            for block in blocks {
                if block.type.uppercased() == expected.rawValue {
                    return block.data
                }
            }
            return nil
        }
        return blocks.first?.data
    }

    /// Normalizes input Data (either PEM ASCII or raw binary DER) into DER Data.
    public static func normalizeToDER(_ data: Data, expectedType: CryptoItemType? = nil) -> Data? {
        if isPEM(data), let pemString = String(data: data, encoding: .utf8) {
            return pemToDER(pemString, expectedType: expectedType)
        }
        return data
    }
}
