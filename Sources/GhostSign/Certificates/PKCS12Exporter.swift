//
//  PKCS12Exporter.swift
//  GhostSign
//
//  Created for Ghost-Sign.
//  Exports RawIdentity (in-memory Certificate & Private Key) into RFC 7292 PKCS#12 (.p12) archives
//  using PBES2 with AES-256-CBC and PBKDF2-HMAC-SHA256, or unencrypted KeyBag.
//  STRICT ARCHITECTURE DIRECTIVE: Zero Apple Keychain dependencies.
//

import Foundation
import Crypto
import _CryptoExtras

public enum PKCS12ExportError: LocalizedError, Equatable {
    case emptyCertificate
    case emptyPrivateKey
    case encryptionFailed(String)
    case encodingFailed(String)

    public var errorDescription: String? {
        switch self {
        case .emptyCertificate:
            return "Certificate DER data cannot be empty."
        case .emptyPrivateKey:
            return "Private key DER data cannot be empty."
        case .encryptionFailed(let reason):
            return "PKCS#12 encryption failed: \(reason)"
        case .encodingFailed(let reason):
            return "PKCS#12 ASN.1 DER encoding failed: \(reason)"
        }
    }
}

public enum PKCS12Exporter {

    /// Exports raw Certificate and Private Key into a PKCS#12 (.p12) archive in RAM.
    ///
    /// - Parameters:
    ///   - certificateDER: Raw ASN.1 DER-encoded X.509 certificate data.
    ///   - privateKeyDER: Raw ASN.1 DER-encoded RSA private key data (PKCS#1 or PKCS#8).
    ///   - password: Encryption password. If empty, encodes unencrypted or with empty password PBES2.
    ///   - friendlyName: Optional user-facing label (e.g. "Apple Development: Jane Doe").
    /// - Returns: Binary PKCS#12 (.p12) data in memory.
    public static func export(
        certificateDER: Data,
        privateKeyDER: Data,
        password: String = "",
        friendlyName: String? = nil
    ) throws -> Data {
        guard !certificateDER.isEmpty else { throw PKCS12ExportError.emptyCertificate }
        guard !privateKeyDER.isEmpty else { throw PKCS12ExportError.emptyPrivateKey }

        // 1. Ensure private key is PKCS#8
        let pkcs8KeyDER: Data
        if let keyPair = try? RSAKeyPair(derRepresentation: privateKeyDER) {
            pkcs8KeyDER = keyPair.pkcs8DER
        } else {
            pkcs8KeyDER = privateKeyDER
        }

        // 2. Build CertBag SafeBag
        let certBag = buildCertBag(certDER: certificateDER, friendlyName: friendlyName)

        // 3. Build KeyBag or ShroudedKeyBag SafeBag
        let keyBag: Data
        if password.isEmpty {
            keyBag = buildUnencryptedKeyBag(pkcs8DER: pkcs8KeyDER, friendlyName: friendlyName)
        } else {
            keyBag = try buildShroudedKeyBag(pkcs8DER: pkcs8KeyDER, password: password, friendlyName: friendlyName)
        }

        // 4. Wrap each bag in SafeContents SEQUENCE
        let certSafeContents = ASN1Helper.sequence(certBag)
        let keySafeContents = ASN1Helper.sequence(keyBag)

        // 5. Wrap SafeContents in ContentInfo (contentType: data)
        let certContentInfo = buildDataContentInfo(content: certSafeContents)
        let keyContentInfo = buildDataContentInfo(content: keySafeContents)

        // 6. AuthenticatedSafe SEQUENCE OF ContentInfo
        let authenticatedSafe = ASN1Helper.sequence(certContentInfo + keyContentInfo)

        // 7. Top-level authSafe ContentInfo (contentType: data)
        let authSafeContentInfo = buildDataContentInfo(content: authenticatedSafe)

        // 8. Top-level PFX SEQUENCE { version: INTEGER 3, authSafe: ContentInfo }
        let versionDER = Data([0x02, 0x01, 0x03]) // INTEGER 3
        let pfx = ASN1Helper.sequence(versionDER + authSafeContentInfo)

        return pfx
    }

    /// Convenience export from `RawIdentity`.
    public static func export(
        identity: RawIdentity,
        password: String = "",
        friendlyName: String? = nil
    ) throws -> Data {
        return try export(
            certificateDER: identity.certificateDER,
            privateKeyDER: identity.privateKeyDER,
            password: password,
            friendlyName: friendlyName
        )
    }

    // MARK: - ASN.1 Builders

    private static func buildDataContentInfo(content: Data) -> Data {
        // ContentInfo ::= SEQUENCE { contentType: 1.2.840.113549.1.7.1, content [0] EXPLICIT OCTET STRING }
        let oidData = Data([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01])
        let octetString = ASN1Helper.octetString(content)
        let explicitContent = ASN1Helper.explicitTag(0, content: octetString)
        return ASN1Helper.sequence(oidData + explicitContent)
    }

    private static func buildCertBag(certDER: Data, friendlyName: String?) -> Data {
        // SafeBag ::= SEQUENCE { bagId: 1.2.840.113549.1.12.10.1.3 (certBag), bagValue [0] EXPLICIT CertBag, bagAttributes }
        let oidCertBag = Data([0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01, 0x03])
        // CertBag ::= SEQUENCE { certId: 1.2.840.113549.1.9.22.1 (x509Certificate), certValue [0] EXPLICIT OCTET STRING }
        let oidX509 = Data([0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x16, 0x01])
        let certOctetString = ASN1Helper.octetString(certDER)
        let explicitCertValue = ASN1Helper.explicitTag(0, content: certOctetString)
        let certBagSequence = ASN1Helper.sequence(oidX509 + explicitCertValue)
        let explicitBagValue = ASN1Helper.explicitTag(0, content: certBagSequence)

        var bagAttributes = Data()
        if let name = friendlyName {
            bagAttributes = buildFriendlyNameAttribute(name)
        }

        return ASN1Helper.sequence(oidCertBag + explicitBagValue + bagAttributes)
    }

    private static func buildUnencryptedKeyBag(pkcs8DER: Data, friendlyName: String?) -> Data {
        // SafeBag ::= SEQUENCE { bagId: 1.2.840.113549.1.12.10.1.1 (keyBag), bagValue [0] EXPLICIT pkcs8DER, bagAttributes }
        let oidKeyBag = Data([0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01, 0x01])
        let explicitValue = ASN1Helper.explicitTag(0, content: pkcs8DER)
        var bagAttributes = Data()
        if let name = friendlyName {
            bagAttributes = buildFriendlyNameAttribute(name)
        }
        return ASN1Helper.sequence(oidKeyBag + explicitValue + bagAttributes)
    }

    private static func buildShroudedKeyBag(pkcs8DER: Data, password: String, friendlyName: String?) throws -> Data {
        // SafeBag ::= SEQUENCE { bagId: 1.2.840.113549.1.12.10.1.2 (pkcs8ShroudedKeyBag), bagValue [0] EXPLICIT EncryptedPrivateKeyInfo, bagAttributes }
        let oidShroudedKeyBag = Data([0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01, 0x02])

        let salt = (0..<16).map { _ in UInt8.random(in: 0...255) }.reduce(into: Data()) { $0.append($1) }
        let iv = (0..<16).map { _ in UInt8.random(in: 0...255) }.reduce(into: Data()) { $0.append($1) }

        let iterations = 2048
        guard let pwData = password.data(using: .utf8),
              let key = CryptoUtilities.pbkdf2SHA256(password: pwData, salt: salt, rounds: iterations, outputLength: 32),
              let ciphertext = CryptoUtilities.aesCBCEncrypt(key: key, iv: iv, plaintext: pkcs8DER) else {
            throw PKCS12ExportError.encryptionFailed("AES-256-CBC PBES2 encryption failed")
        }

        // Build PBES2 AlgorithmIdentifier
        let pbes2AlgId = buildPBES2AlgorithmIdentifier(salt: salt, iterations: iterations, iv: iv)
        let encryptedOctetString = ASN1Helper.octetString(ciphertext)
        let epki = ASN1Helper.sequence(pbes2AlgId + encryptedOctetString)
        let explicitBagValue = ASN1Helper.explicitTag(0, content: epki)

        var bagAttributes = Data()
        if let name = friendlyName {
            bagAttributes = buildFriendlyNameAttribute(name)
        }

        return ASN1Helper.sequence(oidShroudedKeyBag + explicitBagValue + bagAttributes)
    }

    private static func buildPBES2AlgorithmIdentifier(salt: Data, iterations: Int, iv: Data) -> Data {
        let oidPBES2 = Data([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D])
        let oidPBKDF2 = Data([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C])
        let oidAES256CBC = Data([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A])

        // PBKDF2-params ::= SEQUENCE { salt OCTET STRING, iterationCount INTEGER }
        let saltOctet = ASN1Helper.octetString(salt)
        let iterInteger = ASN1Helper.integer(iterations)
        let pbkdf2Params = ASN1Helper.sequence(saltOctet + iterInteger)
        let keyDerivationFunc = ASN1Helper.sequence(oidPBKDF2 + pbkdf2Params)

        // AES-CBC params: OCTET STRING (iv)
        let ivOctet = ASN1Helper.octetString(iv)
        let encryptionScheme = ASN1Helper.sequence(oidAES256CBC + ivOctet)

        let pbes2Params = ASN1Helper.sequence(keyDerivationFunc + encryptionScheme)
        return ASN1Helper.sequence(oidPBES2 + pbes2Params)
    }

    private static func buildFriendlyNameAttribute(_ name: String) -> Data {
        // friendlyName OID: 1.2.840.113549.1.9.20 (06 09 2A 86 48 86 F7 0D 01 09 14)
        let oidFriendlyName = Data([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x14])
        let bmpString = ASN1Helper.bmpString(name)
        let attrValues = ASN1Helper.set(bmpString)
        let attribute = ASN1Helper.sequence(oidFriendlyName + attrValues)
        return ASN1Helper.set(attribute)
    }

    // MARK: - Low-Level ASN.1 Helper

    private enum ASN1Helper {
        static func sequence(_ content: Data) -> Data {
            return Data([0x30]) + encodeLength(content.count) + content
        }

        static func set(_ content: Data) -> Data {
            return Data([0x31]) + encodeLength(content.count) + content
        }

        static func octetString(_ content: Data) -> Data {
            return Data([0x04]) + encodeLength(content.count) + content
        }

        static func explicitTag(_ tagNumber: UInt8, content: Data) -> Data {
            let tagByte = 0xA0 | (tagNumber & 0x1F)
            return Data([tagByte]) + encodeLength(content.count) + content
        }

        static func integer(_ val: Int) -> Data {
            if val == 0 { return Data([0x02, 0x01, 0x00]) }
            var bytes = [UInt8]()
            var v = val
            while v > 0 {
                bytes.insert(UInt8(v & 0xFF), at: 0)
                v >>= 8
            }
            if bytes.first! & 0x80 != 0 {
                bytes.insert(0x00, at: 0)
            }
            return Data([0x02]) + encodeLength(bytes.count) + Data(bytes)
        }

        static func bmpString(_ text: String) -> Data {
            var data = Data()
            for u in text.utf16 {
                data.append(UInt8((u >> 8) & 0xFF))
                data.append(UInt8(u & 0xFF))
            }
            return Data([0x1E]) + encodeLength(data.count) + data
        }

        static func encodeLength(_ length: Int) -> Data {
            if length < 128 {
                return Data([UInt8(length)])
            } else if length <= 0xFF {
                return Data([0x81, UInt8(length)])
            } else if length <= 0xFFFF {
                return Data([0x82, UInt8((length >> 8) & 0xFF), UInt8(length & 0xFF)])
            } else if length <= 0xFFFFFF {
                return Data([0x83, UInt8((length >> 16) & 0xFF), UInt8((length >> 8) & 0xFF), UInt8(length & 0xFF)])
            } else {
                return Data([
                    0x84,
                    UInt8((length >> 24) & 0xFF),
                    UInt8((length >> 16) & 0xFF),
                    UInt8((length >> 8) & 0xFF),
                    UInt8(length & 0xFF)
                ])
            }
        }
    }
}
