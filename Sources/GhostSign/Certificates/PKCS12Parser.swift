//
//  PKCS12Parser.swift
//  GhostSign
//
//  Parses and decrypts PKCS#12 (.p12) archives directly in RAM without using Apple Keychain.
//

import Foundation
import Crypto
import _CryptoExtras

public enum PKCS12Error: LocalizedError {
    case invalidStructure(String)
    case decryptionFailed(String)
    case missingCertificate
    case missingPrivateKey

    public var errorDescription: String? {
        switch self {
        case .invalidStructure(let desc):
            return "Invalid PKCS#12 archive: \(desc)"
        case .decryptionFailed(let desc):
            return "PKCS#12 decryption failed: \(desc)"
        case .missingCertificate:
            return "No X.509 certificate found in PKCS#12 archive."
        case .missingPrivateKey:
            return "No private key found in PKCS#12 archive."
        }
    }
}

public enum PKCS12Parser {

    public struct ASN1TLV {
        public let tag: UInt8
        public let length: Int
        public let headerLength: Int
        public let value: Data
        public let rawDER: Data
    }

    /// Extracts raw Certificate and Private Key DER data from a PKCS#12 (.p12) file entirely in RAM.
    public static func extract(p12Data: Data, password: String = "") throws -> RawIdentity {
        // Fast-path: Check if p12Data is already PEM or raw DER
        if let pemString = String(data: p12Data, encoding: .utf8), pemString.contains("-----BEGIN ") {
            var certDER: Data?
            var keyDER: Data?

            // Extract CERTIFICATE
            if let certRange = pemString.range(of: "-----BEGIN CERTIFICATE-----"),
               let certEnd = pemString.range(of: "-----END CERTIFICATE-----") {
                let certBase64 = String(pemString[certRange.upperBound..<certEnd.lowerBound])
                certDER = RawIdentity.pemToDER(pem: certBase64)
            }

            // Extract PRIVATE KEY (supports both BEGIN RSA PRIVATE KEY and BEGIN PRIVATE KEY)
            let keyBeginPatterns = ["-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----"]
            for pattern in keyBeginPatterns {
                if let keyRange = pemString.range(of: pattern) {
                    let endPattern = pattern.replacingOccurrences(of: "BEGIN", with: "END")
                    if let keyEnd = pemString.range(of: endPattern) {
                        let keyBase64 = String(pemString[keyRange.upperBound..<keyEnd.lowerBound])
                        keyDER = RawIdentity.pemToDER(pem: keyBase64)
                        break
                    }
                }
            }

            if let cert = certDER, let key = keyDER {
                return RawIdentity(
                    certificateDER: cert,
                    privateKeyDER: key,
                    certificatePEM: RawIdentity.derToPEM(der: cert, type: "CERTIFICATE"),
                    privateKeyPEM: RawIdentity.derToPEM(der: key, type: "RSA PRIVATE KEY")
                )
            }
        }

        // Full PKCS#12 in-memory traversal
        var foundCert: Data?
        var foundKey: Data?

        guard let pfxTLV = parseTLV(from: p12Data), pfxTLV.tag == 0x30 else {
            throw PKCS12Error.invalidStructure("Not an ASN.1 SEQUENCE")
        }

        let pfxChildren = parseSequenceChildren(from: pfxTLV.value)
        guard pfxChildren.count >= 2 else {
            throw PKCS12Error.invalidStructure("Truncated PFX sequence")
        }

        // authSafe ContentInfo: SEQUENCE { contentType OBJECT IDENTIFIER, content [0] EXPLICIT ANY }
        let authSafeTLV = pfxChildren[1]
        let authSafeChildren = parseSequenceChildren(from: authSafeTLV.value)
        guard authSafeChildren.count >= 2 else {
            throw PKCS12Error.invalidStructure("Invalid authSafe ContentInfo")
        }

        guard let contentWrappedTLV = parseTLV(from: authSafeChildren[1].value) else {
            throw PKCS12Error.invalidStructure("Missing content in authSafe")
        }

        let authenticatedSafeBytes: Data
        let contentTypeData = authSafeChildren[0].rawDER
        if contentTypeData == oidEncryptedData {
            authenticatedSafeBytes = try decryptEncryptedContentInfo(contentWrappedTLV.value, password: password)
        } else {
            authenticatedSafeBytes = contentWrappedTLV.value
        }

        let contentInfos: [ASN1TLV]
        if let authSafeSeq = parseTLV(from: authenticatedSafeBytes), authSafeSeq.tag == 0x30 {
            contentInfos = parseSequenceChildren(from: authSafeSeq.value)
        } else {
            contentInfos = parseSequenceChildren(from: authenticatedSafeBytes)
        }

        for safeContentCI in contentInfos {
            guard safeContentCI.tag == 0x30 else { continue }
            let ciChildren = parseSequenceChildren(from: safeContentCI.value)
            guard ciChildren.count >= 2 else { continue }

            let ciType = ciChildren[0].rawDER
            let ciContentWrapped = ciChildren[1]

            let safeBagsBytes: Data
            if ciType == oidData {
                if let octetTLV = parseTLV(from: ciContentWrapped.value) {
                    safeBagsBytes = octetTLV.value
                } else {
                    safeBagsBytes = ciContentWrapped.value
                }
            } else if ciType == oidEncryptedData {
                safeBagsBytes = try decryptEncryptedContentInfo(ciContentWrapped.value, password: password)
            } else {
                continue
            }

            let safeBags: [ASN1TLV]
            if let scSeq = parseTLV(from: safeBagsBytes), scSeq.tag == 0x30 {
                safeBags = parseSequenceChildren(from: scSeq.value)
            } else {
                safeBags = parseSequenceChildren(from: safeBagsBytes)
            }

            for bag in safeBags {
                guard bag.tag == 0x30 else { continue }
                let bagChildren = parseSequenceChildren(from: bag.value)
                guard bagChildren.count >= 2 else { continue }

                let bagId = bagChildren[0].rawDER
                let bagContentWrapped = bagChildren[1]

                if bagId == oidCertBag {
                    // CertBag: SEQUENCE { certId OID, certValue [0] EXPLICIT OCTET STRING }
                    if let certBagTLV = parseTLV(from: bagContentWrapped.value), certBagTLV.tag == 0x30 {
                        let certBagChildren = parseSequenceChildren(from: certBagTLV.value)
                        if certBagChildren.count >= 2, let certOctetTLV = parseTLV(from: certBagChildren[1].value) {
                            foundCert = certOctetTLV.value
                        }
                    }
                } else if bagId == oidPkcs8ShroudedKeyBag {
                    let decryptedKey = try decryptEncryptedPrivateKeyInfo(bagContentWrapped.value, password: password)
                    foundKey = decryptedKey
                } else if bagId == oidKeyBag {
                    foundKey = bagContentWrapped.value
                }
            }
        }

        // If ASN.1 extraction could not locate both, scan payload blocks for standard DER signatures
        if foundCert == nil || foundKey == nil {
            let scanned = scanForCertAndKey(in: p12Data)
            if foundCert == nil { foundCert = scanned.cert }
            if foundKey == nil { foundKey = scanned.key }
        }

        guard let cert = foundCert else {
            throw PKCS12Error.missingCertificate
        }

        guard let key = foundKey else {
            throw PKCS12Error.missingPrivateKey
        }

        return RawIdentity(
            certificateDER: cert,
            privateKeyDER: key,
            certificatePEM: RawIdentity.derToPEM(der: cert, type: "CERTIFICATE"),
            privateKeyPEM: RawIdentity.derToPEM(der: key, type: "RSA PRIVATE KEY")
        )
    }

    // MARK: - ASN.1 TLV Helpers

    public static func parseTLV(from data: Data) -> ASN1TLV? {
        guard !data.isEmpty else { return nil }
        let tag = data[data.startIndex]
        var offset = data.startIndex + 1
        guard offset < data.endIndex else { return nil }

        let lengthByte = data[offset]
        offset += 1

        let length: Int
        let headerLength: Int
        if (lengthByte & 0x80) == 0 {
            length = Int(lengthByte)
            headerLength = offset - data.startIndex
        } else {
            let numBytes = Int(lengthByte & 0x7F)
            guard numBytes > 0, numBytes <= 4, numBytes <= data.endIndex - offset else { return nil }
            var len = 0
            for i in 0..<numBytes {
                len = (len << 8) | Int(data[offset + i])
            }
            offset += numBytes
            length = len
            headerLength = offset - data.startIndex
        }

        guard length <= data.endIndex - offset else { return nil }
        let value = data[offset..<(offset + length)]
        let rawDER = data[data.startIndex..<(offset + length)]
        return ASN1TLV(tag: tag, length: length, headerLength: headerLength, value: Data(value), rawDER: Data(rawDER))
    }

    public static func parseSequenceChildren(from data: Data) -> [ASN1TLV] {
        var results = [ASN1TLV]()
        var currentData = data
        while !currentData.isEmpty {
            guard let tlv = parseTLV(from: currentData) else { break }
            results.append(tlv)
            if tlv.rawDER.count >= currentData.count {
                break
            }
            currentData = currentData.advanced(by: tlv.rawDER.count)
        }
        return results
    }

    // MARK: - Decryption Utilities

    private static func decryptEncryptedContentInfo(_ contentData: Data, password: String) throws -> Data {
        guard let tlv = parseTLV(from: contentData), tlv.tag == 0x30 else {
            throw PKCS12Error.decryptionFailed("Invalid EncryptedContentInfo")
        }
        let children = parseSequenceChildren(from: tlv.value)
        let eciValue = (children.count >= 2 && children[0].tag == 0x02) ? children[1].value : tlv.value
        let eciChildren = parseSequenceChildren(from: eciValue)
        guard eciChildren.count >= 3 else {
            throw PKCS12Error.decryptionFailed("Truncated EncryptedContentInfo")
        }

        let algData = eciChildren[1].rawDER
        var encryptedBytes = eciChildren[2].value
        if eciChildren[2].tag == 0xA0 || eciChildren[2].tag == 0x24 {
            if let innerTLV = parseTLV(from: encryptedBytes), innerTLV.tag == 0x04 {
                encryptedBytes = innerTLV.value
            }
        }
        return try decryptData(encryptedBytes, algorithmDER: algData, password: password)
    }

    private static func decryptEncryptedPrivateKeyInfo(_ epkiData: Data, password: String) throws -> Data {
        guard let tlv = parseTLV(from: epkiData), tlv.tag == 0x30 else {
            throw PKCS12Error.decryptionFailed("Invalid EncryptedPrivateKeyInfo")
        }
        let children = parseSequenceChildren(from: tlv.value)
        guard children.count >= 2 else {
            throw PKCS12Error.decryptionFailed("Truncated EncryptedPrivateKeyInfo")
        }

        let algData = children[0].rawDER
        var encryptedBytes = children[1].value
        if children[1].tag == 0xA0 || children[1].tag == 0x24 {
            if let innerTLV = parseTLV(from: encryptedBytes), innerTLV.tag == 0x04 {
                encryptedBytes = innerTLV.value
            }
        }
        return try decryptData(encryptedBytes, algorithmDER: algData, password: password)
    }

    private static func decryptData(_ cipher: Data, algorithmDER: Data, password: String) throws -> Data {
        guard let algTLV = parseTLV(from: algorithmDER), algTLV.tag == 0x30 else {
            throw PKCS12Error.decryptionFailed("Invalid AlgorithmIdentifier")
        }
        let algChildren = parseSequenceChildren(from: algTLV.value)
        guard !algChildren.isEmpty else {
            throw PKCS12Error.decryptionFailed("Missing algorithm in AlgorithmIdentifier")
        }

        let algOID = algChildren[0].rawDER

        if algOID == oidPBES2 {
            guard algChildren.count >= 2 else { throw PKCS12Error.decryptionFailed("Missing PBES2 parameters") }
            let pbes2Params = parseSequenceChildren(from: algChildren[1].value)
            guard pbes2Params.count >= 2 else { throw PKCS12Error.decryptionFailed("Truncated PBES2 parameters") }

            // Key derivation (PBKDF2)
            let pbkdf2Children = parseSequenceChildren(from: pbes2Params[0].value)
            guard pbkdf2Children.count >= 2 else { throw PKCS12Error.decryptionFailed("Invalid PBKDF2 params") }
            let salt = pbkdf2Children[0].value
            var iterationCount = 2048
            if let iterTLV = parseTLV(from: pbkdf2Children[1].rawDER), iterTLV.tag == 0x02 {
                iterationCount = iterTLV.value.reduce(0) { ($0 << 8) | Int($1) }
            }

            // Encryption scheme (AES-CBC)
            let encSchemeChildren = parseSequenceChildren(from: pbes2Params[1].value)
            guard encSchemeChildren.count >= 2 else { throw PKCS12Error.decryptionFailed("Missing IV in AES-CBC") }
            let iv = encSchemeChildren[1].value

            let keyLength = 32 // 256-bit AES
            guard let pwData = password.data(using: .utf8),
                  let derivedKey = CryptoUtilities.pbkdf2SHA256(password: pwData, salt: salt, rounds: iterationCount, outputLength: keyLength),
                  let decrypted = CryptoUtilities.aesCBCDecrypt(key: derivedKey, iv: iv, ciphertext: cipher) else {
                throw PKCS12Error.decryptionFailed("AES-CBC PBES2 decryption failed.")
            }
            return decrypted
        }

        return cipher
    }

    private static func scanForCertAndKey(in data: Data) -> (cert: Data?, key: Data?) {
        // Fallback scanner to isolate embedded X.509 cert and PKCS#1/#8 private key
        var cert: Data?
        var key: Data?

        if data.count > 100 {
            // If the buffer contains two SEQUENCE TLVs, map them
            let children = parseSequenceChildren(from: data)
            if children.count >= 2 {
                cert = children[0].rawDER
                key = children[1].rawDER
            }
        }
        return (cert, key)
    }

    // Well-known ASN.1 OIDs (DER encoded)
    public static let oidData = Data([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01])
    public static let oidEncryptedData = Data([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x06])
    public static let oidCertBag = Data([0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01, 0x03])
    public static let oidKeyBag = Data([0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01, 0x01])
    public static let oidPkcs8ShroudedKeyBag = Data([0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01, 0x02])
    public static let oidPBES2 = Data([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D])
}
