//
//  CSRGenerator.swift
//  GhostSign
//
//  Created for Ghost-Sign Milestone 1.
//  Zero-dependency PKCS#10 Certificate Signing Request (CSR) Generator and Verifier.
//  STRICT ARCHITECTURE DIRECTIVE: In-memory Raw Crypto without Apple Keychain.
//

import Foundation
import Crypto
import _CryptoExtras

// MARK: - CSRSubject Model

/// Subject Distinguished Name attributes for a PKCS#10 Certificate Signing Request (RFC 2986 / RFC 5280).
public struct CSRSubject: Sendable, Equatable, Hashable {
    /// Common Name (e.g. "Apple Development: Jane Doe (ABC1234567)"). Required.
    public var commonName: String

    /// Two-letter country code (ISO 3166-1 alpha-2, e.g. "US"). Default: "US".
    public var country: String?

    /// Organization name (e.g. "Jane Doe (Individual)" or developer team name). Optional.
    public var organization: String?

    /// Organizational Unit name (typically the 10-character Apple Team ID, e.g. "7XXXXXXXXX"). Optional.
    public var organizationalUnit: String?

    /// State or Province name (e.g. "California" or "CA"). Optional.
    public var state: String?

    /// Locality or City name (e.g. "Cupertino"). Optional.
    public var locality: String?

    /// Designating initializer with all 6 configurable Distinguished Name attributes.
    public init(
        commonName: String,
        country: String? = "US",
        organization: String? = nil,
        organizationalUnit: String? = nil,
        state: String? = nil,
        locality: String? = nil
    ) {
        self.commonName = commonName
        self.country = country
        self.organization = organization
        self.organizationalUnit = organizationalUnit
        self.state = state
        self.locality = locality
    }

    /// Convenience initializer matching PROJECT.md interface contract.
    public init(
        commonName: String,
        country: String? = "US",
        organization: String? = nil,
        organizationalUnit: String? = nil
    ) {
        self.init(
            commonName: commonName,
            country: country,
            organization: organization,
            organizationalUnit: organizationalUnit,
            state: nil,
            locality: nil
        )
    }

    /// Convenience factory for Apple Development Certificate Subject DN.
    /// Generates Common Name matching Apple's standard: `Apple Development: <Name> (<UserID>)`.
    public static func appleDevelopment(
        name: String,
        userID: String,
        teamID: String? = nil,
        teamName: String? = nil
    ) -> CSRSubject {
        CSRSubject(
            commonName: "Apple Development: \(name) (\(userID))",
            country: "US",
            organization: teamName,
            organizationalUnit: teamID
        )
    }

    /// Convenience factory for Apple Distribution Certificate Subject DN.
    /// Generates Common Name matching Apple's standard: `Apple Distribution: <TeamName> (<TeamID>)`.
    public static func appleDistribution(
        teamName: String,
        teamID: String
    ) -> CSRSubject {
        CSRSubject(
            commonName: "Apple Distribution: \(teamName) (\(teamID))",
            country: "US",
            organization: teamName,
            organizationalUnit: teamID
        )
    }
}

// MARK: - CSRGeneratorError

/// Strongly typed errors encountered during CSR generation, serialization, or verification.
public enum CSRGeneratorError: Error, LocalizedError, Equatable {
    case emptyCommonName
    case invalidCountryCode(String)
    case signatureFailed(String)
    case invalidASN1Structure(String)
    case invalidPEMFormat(String)
    case verificationFailed(String)

    public var errorDescription: String? {
        switch self {
        case .emptyCommonName:
            return "Subject commonName cannot be empty."
        case .invalidCountryCode(let code):
            return "Country code must be a 2-letter ISO 3166-1 alpha-2 code, got '\(code)'."
        case .signatureFailed(let reason):
            return "CSR signature calculation failed: \(reason)"
        case .invalidASN1Structure(let reason):
            return "Invalid ASN.1 structure in CSR: \(reason)"
        case .invalidPEMFormat(let reason):
            return "Failed to parse PEM certificate request: \(reason)"
        case .verificationFailed(let reason):
            return "CSR self-signature verification failed: \(reason)"
        }
    }
}

/// Typealias for backward compatibility with alternative error naming.
public typealias CSRError = CSRGeneratorError

// MARK: - CSRGenerator

/// Standard PKCS#10 Certificate Signing Request (CSR) generator and verifier.
public enum CSRGenerator {

    /// Generates a PKCS#10 Certificate Signing Request signed with SHA-256 with RSA encryption (PKCS#1 v1.5).
    ///
    /// - Parameters:
    ///   - keyPair: The RSA key pair used to sign and provide the public key.
    ///   - subject: The subject distinguished name.
    /// - Returns: A tuple containing the binary DER-encoded CSR and ASCII PEM-armored CSR.
    public static func generateCSR(
        keyPair: RSAKeyPair,
        subject: CSRSubject
    ) throws -> (der: Data, pem: String) {
        return try generateCSR(
            privateKey: keyPair.privateKey,
            publicKeySPKI: keyPair.publicKeyDER,
            subject: subject
        )
    }

    /// Generates a PKCS#10 Certificate Signing Request using a private key and Subject details.
    public static func generateCSR(
        privateKey: _RSA.Signing.PrivateKey,
        subject: CSRSubject
    ) throws -> (der: Data, pem: String) {
        return try generateCSR(
            privateKey: privateKey,
            publicKeySPKI: privateKey.publicKey.derRepresentation,
            subject: subject
        )
    }

    /// Core generator taking private key, public key SubjectPublicKeyInfo bytes, and subject.
    public static func generateCSR(
        privateKey: _RSA.Signing.PrivateKey,
        publicKeySPKI: Data,
        subject: CSRSubject
    ) throws -> (der: Data, pem: String) {
        // 1. Validate inputs
        let trimmedCN = subject.commonName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedCN.isEmpty else {
            throw CSRGeneratorError.emptyCommonName
        }

        if let country = subject.country, !country.isEmpty && country.count != 2 {
            throw CSRGeneratorError.invalidCountryCode(country)
        }

        // 2. Build Subject Name SEQUENCE of SETs
        let subjectDER = try buildSubjectDER(subject: subject)

        // 3. Build Attributes: [0] IMPLICIT empty (tag 0xA0, length 0x00 -> A0 00)
        let attributesDER = ASN1DER.contextSpecific0(Data())

        // 4. Build CertificationRequestInfo (CRI)
        // CertificationRequestInfo ::= SEQUENCE { version (0), subject, subjectPKInfo, attributes }
        let criDER = ASN1DER.sequence(
            ASN1DER.integer(0) +
            subjectDER +
            publicKeySPKI +
            attributesDER
        )

        // 5. Compute SHA-256 Digest of CRI
        let digest = SHA256.hash(data: criDER)

        // 6. Sign Digest with RSA PKCS#1 v1.5 padding
        let signature: _RSA.Signing.RSASignature
        do {
            signature = try privateKey.signature(for: digest, padding: .insecurePKCS1v1_5)
        } catch {
            throw CSRGeneratorError.signatureFailed(error.localizedDescription)
        }

        // 7. SignatureAlgorithmIdentifier: sha256WithRSAEncryption (1.2.840.113549.1.1.11) with NULL parameter
        let sigAlgDER = ASN1DER.sequence(
            ASN1DER.oidSha256WithRSAEncryption +
            ASN1DER.null()
        )

        // 8. Signature BIT STRING: leading 0x00 unused bits + 256 bytes signature
        let sigBitStringDER = ASN1DER.bitString(signature.rawRepresentation)

        // 9. Outer CertificationRequest: SEQUENCE { cri, sigAlg, sigBitString }
        let csrDER = ASN1DER.sequence(criDER + sigAlgDER + sigBitStringDER)

        // 10. PEM Armored Representation
        let csrPEM = derToPEM(csrDER)

        return (der: csrDER, pem: csrPEM)
    }

    /// Generates only binary DER-encoded CSR.
    public static func generateCSRDER(
        keyPair: RSAKeyPair,
        subject: CSRSubject
    ) throws -> Data {
        try generateCSR(keyPair: keyPair, subject: subject).der
    }

    /// Generates only ASCII PEM-armored CSR.
    public static func generateCSRPEM(
        keyPair: RSAKeyPair,
        subject: CSRSubject
    ) throws -> String {
        try generateCSR(keyPair: keyPair, subject: subject).pem
    }

    /// Verifies the cryptographic self-signature of a PKCS#10 CSR in binary DER format.
    /// If `publicKey` is nil or omitted, the public key is extracted directly from the CSR's SubjectPublicKeyInfo.
    public static func verify(
        csrDER: Data,
        publicKey: _RSA.Signing.PublicKey? = nil
    ) -> Bool {
        guard let outer = ASN1DER.parseTLV(from: csrDER), outer.tag == 0x30 else {
            return false
        }

        let children = ASN1DER.parseChildren(from: outer.value)
        guard children.count >= 3 else {
            return false
        }

        let criRaw = children[0].rawDER
        let sigAlgTLV = children[1]
        let sigBitsTLV = children[2]

        // Verify AlgorithmIdentifier contains sha256WithRSAEncryption OID (1.2.840.113549.1.1.11)
        guard sigAlgTLV.value.starts(with: ASN1DER.oidSha256WithRSAEncryption) else {
            return false
        }

        // Verify Signature BIT STRING (tag 0x03, unused bits == 0x00, followed by signature bytes)
        guard sigBitsTLV.tag == 0x03, sigBitsTLV.value.count > 1 else {
            return false
        }
        guard sigBitsTLV.value[sigBitsTLV.value.startIndex] == 0x00 else {
            return false
        }
        let rawSig = sigBitsTLV.value.dropFirst()
        guard rawSig.count >= 256 else {
            return false
        }

        // Resolve public key
        let verificationKey: _RSA.Signing.PublicKey
        if let key = publicKey {
            verificationKey = key
        } else {
            guard let criOuter = ASN1DER.parseTLV(from: criRaw), criOuter.tag == 0x30 else {
                return false
            }
            let criChildren = ASN1DER.parseChildren(from: criOuter.value)
            guard criChildren.count >= 3 else {
                return false
            }
            let spkiRaw = criChildren[2].rawDER
            guard let key = try? _RSA.Signing.PublicKey(derRepresentation: spkiRaw) else {
                return false
            }
            verificationKey = key
        }

        // Verify signature over CRI DER bytes
        let digest = SHA256.hash(data: criRaw)
        let rsaSig = _RSA.Signing.RSASignature(rawRepresentation: Data(rawSig))
        return verificationKey.isValidSignature(rsaSig, for: digest, padding: .insecurePKCS1v1_5)
    }

    /// Verifies the cryptographic self-signature of a PKCS#10 CSR in ASCII PEM format.
    public static func verify(
        csrPEM: String,
        publicKey: _RSA.Signing.PublicKey? = nil
    ) -> Bool {
        guard let der = try? pemToDER(csrPEM) else {
            return false
        }
        return verify(csrDER: der, publicKey: publicKey)
    }

    /// Verifies the cryptographic self-signature of a PKCS#10 CSR in binary DER format against a specific public key.
    public static func verify(
        csrDER: Data,
        publicKey: _RSA.Signing.PublicKey
    ) -> Bool {
        return verify(csrDER: csrDER, publicKey: Optional(publicKey))
    }

    /// Verifies the cryptographic self-signature of a PKCS#10 CSR in ASCII PEM format against a specific public key.
    public static func verify(
        csrPEM: String,
        publicKey: _RSA.Signing.PublicKey
    ) -> Bool {
        return verify(csrPEM: csrPEM, publicKey: Optional(publicKey))
    }

    /// Throwing verification helper for DER data.
    public static func verifyCSR(der: Data) throws -> Bool {
        guard let outer = ASN1DER.parseTLV(from: der), outer.tag == 0x30 else {
            throw CSRGeneratorError.invalidASN1Structure("Expected root SEQUENCE (0x30)")
        }
        let result = verify(csrDER: der)
        if !result {
            throw CSRGeneratorError.verificationFailed("CSR signature does not match public key or content")
        }
        return true
    }

    /// Throwing verification helper for PEM string.
    public static func verifyCSR(pem: String) throws -> Bool {
        let der = try pemToDER(pem)
        return try verifyCSR(der: der)
    }

    /// Extracts the Subject attributes from a binary DER-encoded CSR.
    public static func extractSubject(from csrDER: Data) throws -> CSRSubject {
        guard let outer = ASN1DER.parseTLV(from: csrDER), outer.tag == 0x30 else {
            throw CSRGeneratorError.invalidASN1Structure("Expected outer SEQUENCE")
        }
        let children = ASN1DER.parseChildren(from: outer.value)
        guard children.count >= 1 else {
            throw CSRGeneratorError.invalidASN1Structure("Missing CertificationRequestInfo")
        }

        guard let cri = ASN1DER.parseTLV(from: children[0].rawDER), cri.tag == 0x30 else {
            throw CSRGeneratorError.invalidASN1Structure("CRI is not a SEQUENCE")
        }
        let criChildren = ASN1DER.parseChildren(from: cri.value)
        guard criChildren.count >= 2 else {
            throw CSRGeneratorError.invalidASN1Structure("Missing Subject in CRI")
        }

        let subjectContent = criChildren[1].value
        var country: String?
        var state: String?
        var locality: String?
        var organization: String?
        var organizationalUnit: String?
        var commonName: String = ""

        for rdn in ASN1DER.parseChildren(from: subjectContent) where rdn.tag == 0x31 {
            for atv in ASN1DER.parseChildren(from: rdn.value) where atv.tag == 0x30 {
                let parts = ASN1DER.parseChildren(from: atv.value)
                guard parts.count >= 2, parts[0].tag == 0x06 else { continue }
                let oidRaw = parts[0].rawDER
                let valStr = String(data: parts[1].value, encoding: .utf8) ??
                             String(data: parts[1].value, encoding: .ascii) ?? ""

                if oidRaw == ASN1DER.oidCountryName {
                    country = valStr
                } else if oidRaw == ASN1DER.oidStateOrProvinceName {
                    state = valStr
                } else if oidRaw == ASN1DER.oidLocalityName {
                    locality = valStr
                } else if oidRaw == ASN1DER.oidOrganizationName {
                    organization = valStr
                } else if oidRaw == ASN1DER.oidOrganizationalUnitName {
                    organizationalUnit = valStr
                } else if oidRaw == ASN1DER.oidCommonName {
                    commonName = valStr
                }
            }
        }

        guard !commonName.isEmpty else {
            throw CSRGeneratorError.invalidASN1Structure("CommonName not found in Subject")
        }

        return CSRSubject(
            commonName: commonName,
            country: country,
            organization: organization,
            organizationalUnit: organizationalUnit,
            state: state,
            locality: locality
        )
    }

    /// Extracts the Subject attributes from an ASCII PEM-encoded CSR.
    public static func extractSubject(from csrPEM: String) throws -> CSRSubject {
        let der = try pemToDER(csrPEM)
        return try extractSubject(from: der)
    }

    /// Converts raw binary DER data into standard 64-character column PEM ASCII string.
    public static func derToPEM(_ der: Data, tag: String = "CERTIFICATE REQUEST") -> String {
        let base64 = der.base64EncodedString()
        var result = "-----BEGIN \(tag)-----\n"
        var offset = 0
        while offset < base64.count {
            let nextOffset = min(offset + 64, base64.count)
            let startIndex = base64.index(base64.startIndex, offsetBy: offset)
            let endIndex = base64.index(base64.startIndex, offsetBy: nextOffset)
            result.append(String(base64[startIndex..<endIndex]))
            result.append("\n")
            offset = nextOffset
        }
        result.append("-----END \(tag)-----\n")
        return result
    }

    /// Converts a PEM ASCII string to raw binary DER data.
    public static func pemToDER(_ pem: String) throws -> Data {
        let lines = pem.components(separatedBy: .newlines)
        var base64 = ""
        var inBlock = false
        var openedTag = ""
        var blockClosed = false

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty { continue }

            if trimmed.hasPrefix("-----BEGIN ") && trimmed.hasSuffix("-----") {
                if inBlock {
                    throw CSRGeneratorError.invalidPEMFormat("Nested or unclosed PEM delimiter before '\(trimmed)'")
                }
                guard trimmed.count > 16 else { continue }
                let tag = String(trimmed.dropFirst(11).dropLast(5))
                if tag == "CERTIFICATE REQUEST" || tag == "NEW CERTIFICATE REQUEST" {
                    inBlock = true
                    openedTag = tag
                    base64 = ""
                }
            } else if trimmed.hasPrefix("-----END ") && trimmed.hasSuffix("-----") {
                if inBlock {
                    guard trimmed.count > 14 else {
                        throw CSRGeneratorError.invalidPEMFormat("Malformed PEM closing delimiter '\(trimmed)'")
                    }
                    let endTag = String(trimmed.dropFirst(9).dropLast(5))
                    if endTag == openedTag {
                        inBlock = false
                        blockClosed = true
                        break
                    } else {
                        throw CSRGeneratorError.invalidPEMFormat("Mismatched PEM delimiters: opened with '-----BEGIN \(openedTag)-----' but closed with '\(trimmed)'")
                    }
                }
            } else if inBlock {
                if trimmed.hasPrefix("-----") {
                    throw CSRGeneratorError.invalidPEMFormat("Unexpected delimiter or armor header inside PEM block: '\(trimmed)'")
                }
                base64.append(trimmed)
            }
        }

        if inBlock && !blockClosed {
            throw CSRGeneratorError.invalidPEMFormat("Truncated PEM: missing closing delimiter '-----END \(openedTag)-----'")
        }

        guard blockClosed else {
            throw CSRGeneratorError.invalidPEMFormat("No valid base64-encoded CERTIFICATE REQUEST block found in PEM")
        }

        guard !base64.isEmpty, let der = Data(base64Encoded: base64, options: .ignoreUnknownCharacters) else {
            throw CSRGeneratorError.invalidPEMFormat("Invalid Base64 payload in CERTIFICATE REQUEST block")
        }
        return der
    }

    // MARK: - Private Helpers

    private static func buildSubjectDER(subject: CSRSubject) throws -> Data {
        let trimmedCN = subject.commonName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedCN.isEmpty else {
            throw CSRGeneratorError.emptyCommonName
        }

        var rdns = Data()

        // 1. CountryName: PrintableString (0x13), exactly 2 letters per RFC 5280
        if let country = subject.country, !country.isEmpty {
            guard country.count == 2, country.allSatisfy({ $0.isASCII && $0.isLetter }) else {
                throw CSRGeneratorError.invalidCountryCode(country)
            }
            let atv = ASN1DER.sequence(ASN1DER.oidCountryName + ASN1DER.printableString(country.uppercased()))
            rdns.append(ASN1DER.set(atv))
        }

        // 2. StateOrProvinceName: UTF8String (0x0C)
        if let state = subject.state, !state.isEmpty {
            let atv = ASN1DER.sequence(ASN1DER.oidStateOrProvinceName + ASN1DER.utf8String(state))
            rdns.append(ASN1DER.set(atv))
        }

        // 3. LocalityName: UTF8String (0x0C)
        if let locality = subject.locality, !locality.isEmpty {
            let atv = ASN1DER.sequence(ASN1DER.oidLocalityName + ASN1DER.utf8String(locality))
            rdns.append(ASN1DER.set(atv))
        }

        // 4. OrganizationName: UTF8String (0x0C)
        if let org = subject.organization, !org.isEmpty {
            let atv = ASN1DER.sequence(ASN1DER.oidOrganizationName + ASN1DER.utf8String(org))
            rdns.append(ASN1DER.set(atv))
        }

        // 5. OrganizationalUnitName: UTF8String (0x0C)
        if let ou = subject.organizationalUnit, !ou.isEmpty {
            let atv = ASN1DER.sequence(ASN1DER.oidOrganizationalUnitName + ASN1DER.utf8String(ou))
            rdns.append(ASN1DER.set(atv))
        }

        // 6. CommonName: UTF8String (0x0C)
        let cnAtv = ASN1DER.sequence(ASN1DER.oidCommonName + ASN1DER.utf8String(trimmedCN))
        rdns.append(ASN1DER.set(cnAtv))

        return ASN1DER.sequence(rdns)
    }
}

// MARK: - Internal Canonical ASN.1 DER Encoder & Parser

enum ASN1DER {

    // Standard Pre-encoded OIDs
    static let oidSha256WithRSAEncryption = Data([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B])
    static let oidRsaEncryption           = Data([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])
    static let oidCountryName             = Data([0x06, 0x03, 0x55, 0x04, 0x06])
    static let oidStateOrProvinceName     = Data([0x06, 0x03, 0x55, 0x04, 0x08])
    static let oidLocalityName            = Data([0x06, 0x03, 0x55, 0x04, 0x07])
    static let oidOrganizationName        = Data([0x06, 0x03, 0x55, 0x04, 0x0A])
    static let oidOrganizationalUnitName  = Data([0x06, 0x03, 0x55, 0x04, 0x0B])
    static let oidCommonName              = Data([0x06, 0x03, 0x55, 0x04, 0x03])

    /// Encodes a length integer according to canonical DER rules.
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

    /// Encodes a general Tag-Length-Value triple.
    static func tlv(tag: UInt8, value: Data) -> Data {
        var result = Data([tag])
        result.append(encodeLength(value.count))
        result.append(value)
        return result
    }

    /// Encodes a SEQUENCE (tag 0x30).
    static func sequence(_ content: Data) -> Data {
        return tlv(tag: 0x30, value: content)
    }

    /// Encodes a SET (tag 0x31).
    static func set(_ content: Data) -> Data {
        return tlv(tag: 0x31, value: content)
    }

    /// Encodes an INTEGER (tag 0x02).
    static func integer(_ value: Int) -> Data {
        if value == 0 {
            return Data([0x02, 0x01, 0x00])
        }
        var temp = value
        var bytes: [UInt8] = []
        while temp > 0 {
            bytes.insert(UInt8(temp & 0xFF), at: 0)
            temp >>= 8
        }
        if let first = bytes.first, (first & 0x80) != 0 {
            bytes.insert(0x00, at: 0)
        }
        return tlv(tag: 0x02, value: Data(bytes))
    }

    /// Encodes a PrintableString (tag 0x13).
    static func printableString(_ string: String) -> Data {
        return tlv(tag: 0x13, value: Data(string.utf8))
    }

    /// Encodes a UTF8String (tag 0x0C).
    static func utf8String(_ string: String) -> Data {
        return tlv(tag: 0x0C, value: Data(string.utf8))
    }

    /// Encodes an OCTET STRING (tag 0x04).
    static func octetString(_ content: Data) -> Data {
        return tlv(tag: 0x04, value: content)
    }

    /// Encodes a BIT STRING (tag 0x03) with leading unused-bits byte.
    static func bitString(_ content: Data, unusedBits: UInt8 = 0) -> Data {
        var value = Data([unusedBits])
        value.append(content)
        return tlv(tag: 0x03, value: value)
    }

    /// Encodes ASN.1 NULL (05 00).
    static func null() -> Data {
        return Data([0x05, 0x00])
    }

    /// Encodes context-specific constructed tag [0] (0xA0).
    static func contextSpecific0(_ content: Data) -> Data {
        return tlv(tag: 0xA0, value: content)
    }

    // MARK: - DER Parser Helpers

    /// Parses a single TLV from Data at the given offset.
    static func parseTLV(from data: Data, at offset: Int = 0) -> (tag: UInt8, value: Data, totalLength: Int)? {
        guard offset >= 0, offset < data.count else { return nil }
        let base = data.startIndex
        let tag = data[base + offset]
        var current = offset + 1
        guard current < data.count else { return nil }

        let firstLen = data[base + current]
        current += 1

        let length: Int
        if (firstLen & 0x80) == 0 {
            length = Int(firstLen)
        } else {
            let numBytes = Int(firstLen & 0x7F)
            // Cap numBytes <= 4 to prevent integer overflow and reject non-conforming DER lengths
            guard numBytes > 0, numBytes <= 4, numBytes <= data.count - current else { return nil }
            var len = 0
            for i in 0..<numBytes {
                len = (len << 8) | Int(data[base + current + i])
            }
            current += numBytes
            length = len
        }

        // Validate bounds safely without integer addition overflow
        guard length >= 0, length <= data.count - current else { return nil }
        let startIdx = base + current
        let endIdx = startIdx + length
        let value = data.subdata(in: startIdx..<endIdx)
        let total = current + length - offset
        return (tag, value, total)
    }

    /// Parses all consecutive child TLVs within sequence or set content.
    static func parseChildren(from containerContent: Data) -> [(tag: UInt8, value: Data, rawDER: Data, totalLength: Int)] {
        var items: [(tag: UInt8, value: Data, rawDER: Data, totalLength: Int)] = []
        var offset = 0
        let base = containerContent.startIndex
        while offset < containerContent.count {
            guard let tlv = parseTLV(from: containerContent, at: offset) else { break }
            let startIdx = base + offset
            let endIdx = startIdx + tlv.totalLength
            let raw = containerContent.subdata(in: startIdx..<endIdx)
            items.append((tlv.tag, tlv.value, raw, tlv.totalLength))
            offset += tlv.totalLength
        }
        return items
    }
}
