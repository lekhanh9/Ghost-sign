//
//  CSRGeneratorTests.swift
//  GhostSignTests
//
//  Created for Ghost-Sign Milestone 1.
//

import XCTest
@testable import GhostSign
import Crypto
import _CryptoExtras

final class CSRGeneratorTests: XCTestCase {

    func testGenerateCSRAppleDevelopmentSubject() throws {
        let keyPair = try RSAKeyPair()
        let subject = CSRSubject.appleDevelopment(
            name: "Jane Doe",
            userID: "XYZ1234567",
            teamID: "TEAM777777",
            teamName: "Jane Doe (Individual)"
        )

        let (der, pem) = try CSRGenerator.generateCSR(keyPair: keyPair, subject: subject)

        XCTAssertFalse(der.isEmpty)
        XCTAssertTrue(pem.hasPrefix("-----BEGIN CERTIFICATE REQUEST-----\n"))
        XCTAssertTrue(pem.contains("-----END CERTIFICATE REQUEST-----"))

        // Verify with explicit public key
        XCTAssertTrue(CSRGenerator.verify(csrDER: der, publicKey: keyPair.publicKey))
        XCTAssertTrue(CSRGenerator.verify(csrPEM: pem, publicKey: keyPair.publicKey))

        // Verify self-signature without passing public key
        XCTAssertTrue(CSRGenerator.verify(csrDER: der))
        XCTAssertTrue(CSRGenerator.verify(csrPEM: pem))

        // Verify throwing helper
        XCTAssertTrue(try CSRGenerator.verifyCSR(der: der))
        XCTAssertTrue(try CSRGenerator.verifyCSR(pem: pem))
    }

    func testGenerateCSRAppleDistributionSubject() throws {
        let keyPair = try RSAKeyPair()
        let subject = CSRSubject.appleDistribution(
            teamName: "Acme Corp",
            teamID: "ACME123456"
        )

        let (der, pem) = try CSRGenerator.generateCSR(keyPair: keyPair, subject: subject)
        XCTAssertFalse(der.isEmpty)
        XCTAssertTrue(CSRGenerator.verify(csrDER: der, publicKey: keyPair.publicKey))
        XCTAssertTrue(CSRGenerator.verify(csrPEM: pem))

        let extracted = try CSRGenerator.extractSubject(from: der)
        XCTAssertEqual(extracted.commonName, "Apple Distribution: Acme Corp (ACME123456)")
        XCTAssertEqual(extracted.organization, "Acme Corp")
        XCTAssertEqual(extracted.organizationalUnit, "ACME123456")
        XCTAssertEqual(extracted.country, "US")
    }

    func testASN1DERStructureAndAttributesTag() throws {
        let keyPair = try RSAKeyPair()
        let subject = CSRSubject.appleDevelopment(name: "Alice", userID: "ID123", teamID: "TEAM1")
        let der = try CSRGenerator.generateCSRDER(keyPair: keyPair, subject: subject)

        // Outer TLV: SEQUENCE (0x30)
        guard let outerTLV = ASN1DER.parseTLV(from: der) else {
            XCTFail("Failed to parse outer TLV")
            return
        }
        XCTAssertEqual(outerTLV.tag, 0x30)

        let topChildren = ASN1DER.parseChildren(from: outerTLV.value)
        XCTAssertEqual(topChildren.count, 3, "Outer SEQUENCE must have 3 children: CRI, AlgID, Signature")

        let criRaw = topChildren[0].rawDER
        let sigAlgTLV = topChildren[1]
        let sigBitsTLV = topChildren[2]

        // Inspect CRI
        guard let criTLV = ASN1DER.parseTLV(from: criRaw) else {
            XCTFail("Failed to parse CRI")
            return
        }
        XCTAssertEqual(criTLV.tag, 0x30)

        let criChildren = ASN1DER.parseChildren(from: criTLV.value)
        XCTAssertEqual(criChildren.count, 4, "CRI must contain 4 children: Version, Subject, SPKI, Attributes")

        // 1. Version must be INTEGER 0: [0x02, 0x01, 0x00]
        XCTAssertEqual(criChildren[0].rawDER, Data([0x02, 0x01, 0x00]))

        // 2. Subject must be SEQUENCE (0x30)
        XCTAssertEqual(criChildren[1].tag, 0x30)

        // 3. SPKI must be SEQUENCE (0x30) and match keyPair.publicKeyDER
        XCTAssertEqual(criChildren[2].tag, 0x30)
        XCTAssertEqual(criChildren[2].rawDER, keyPair.publicKeyDER)

        // 4. Attributes MUST be [0] IMPLICIT empty: [0xA0, 0x00]
        XCTAssertEqual(criChildren[3].tag, 0xA0)
        XCTAssertEqual(criChildren[3].rawDER, Data([0xA0, 0x00]), "Attributes must be encoded as A0 00")

        // Inspect Signature AlgorithmIdentifier: sha256WithRSAEncryption + NULL
        XCTAssertEqual(sigAlgTLV.tag, 0x30)
        XCTAssertTrue(sigAlgTLV.value.starts(with: ASN1DER.oidSha256WithRSAEncryption))
        XCTAssertEqual(sigAlgTLV.value.suffix(2), Data([0x05, 0x00]))

        // Inspect Signature BIT STRING: tag 0x03, unused bits 0x00, 256 bytes signature
        XCTAssertEqual(sigBitsTLV.tag, 0x03)
        XCTAssertEqual(sigBitsTLV.value.count, 257)
        XCTAssertEqual(sigBitsTLV.value[sigBitsTLV.value.startIndex], 0x00, "Unused bits prefix must be 0x00")
    }

    func testAllSubjectFieldsConfigurable() throws {
        let keyPair = try RSAKeyPair()
        let subject = CSRSubject(
            commonName: "Apple Development: Full Subject Test (USER123)",
            country: "US",
            organization: "My Organization",
            organizationalUnit: "TEAM_OU_1",
            state: "California",
            locality: "Cupertino"
        )

        let (der, pem) = try CSRGenerator.generateCSR(keyPair: keyPair, subject: subject)
        XCTAssertTrue(CSRGenerator.verify(csrDER: der))

        let extractedFromDER = try CSRGenerator.extractSubject(from: der)
        XCTAssertEqual(extractedFromDER.commonName, "Apple Development: Full Subject Test (USER123)")
        XCTAssertEqual(extractedFromDER.country, "US")
        XCTAssertEqual(extractedFromDER.organization, "My Organization")
        XCTAssertEqual(extractedFromDER.organizationalUnit, "TEAM_OU_1")
        XCTAssertEqual(extractedFromDER.state, "California")
        XCTAssertEqual(extractedFromDER.locality, "Cupertino")

        let extractedFromPEM = try CSRGenerator.extractSubject(from: pem)
        XCTAssertEqual(extractedFromPEM, extractedFromDER)
    }

    func testMinimalSubjectOnlyCommonName() throws {
        let keyPair = try RSAKeyPair()
        let subject = CSRSubject(
            commonName: "Minimal Common Name Only",
            country: nil
        )

        let (der, _) = try CSRGenerator.generateCSR(keyPair: keyPair, subject: subject)
        XCTAssertTrue(CSRGenerator.verify(csrDER: der))

        let extracted = try CSRGenerator.extractSubject(from: der)
        XCTAssertEqual(extracted.commonName, "Minimal Common Name Only")
        XCTAssertNil(extracted.country)
    }

    func testEmptyCommonNameThrows() throws {
        let keyPair = try RSAKeyPair()
        let subject = CSRSubject(commonName: "   ")

        XCTAssertThrowsError(try CSRGenerator.generateCSR(keyPair: keyPair, subject: subject)) { error in
            guard let csrError = error as? CSRGeneratorError else {
                XCTFail("Expected CSRGeneratorError but got \(error)")
                return
            }
            XCTAssertEqual(csrError, .emptyCommonName)
        }
    }

    func testInvalidCountryCodeThrows() throws {
        let keyPair = try RSAKeyPair()
        let subject = CSRSubject(commonName: "Valid Name", country: "USA")

        XCTAssertThrowsError(try CSRGenerator.generateCSR(keyPair: keyPair, subject: subject)) { error in
            guard let csrError = error as? CSRGeneratorError else {
                XCTFail("Expected CSRGeneratorError but got \(error)")
                return
            }
            guard case .invalidCountryCode(let code) = csrError else {
                XCTFail("Expected invalidCountryCode but got \(csrError)")
                return
            }
            XCTAssertEqual(code, "USA")
        }
    }

    func testTamperingWithCRIInvalidatesSignature() throws {
        let keyPair = try RSAKeyPair()
        let subject = CSRSubject(commonName: "Original Subject")
        var (der, _) = try CSRGenerator.generateCSR(keyPair: keyPair, subject: subject)
        XCTAssertTrue(CSRGenerator.verify(csrDER: der))

        // Mutate a byte in the middle of CRI (offset ~30)
        let tamperIndex = 30
        guard tamperIndex < der.count else {
            XCTFail("CSR DER too short")
            return
        }
        der[tamperIndex] ^= 0xFF

        // Verification must now fail
        XCTAssertFalse(CSRGenerator.verify(csrDER: der))
        XCTAssertThrowsError(try CSRGenerator.verifyCSR(der: der))
    }

    func testPEMDERConversionRoundtrip() throws {
        let keyPair = try RSAKeyPair()
        let subject = CSRSubject.appleDevelopment(name: "Roundtrip", userID: "RT1")
        let derOriginal = try CSRGenerator.generateCSRDER(keyPair: keyPair, subject: subject)

        let pemArmored = CSRGenerator.derToPEM(derOriginal)
        let derDecoded = try CSRGenerator.pemToDER(pemArmored)

        XCTAssertEqual(derDecoded, derOriginal)
        XCTAssertTrue(CSRGenerator.verify(csrDER: derDecoded))
    }

    func testAppleDeveloperPortalEnvelopeCompatibility() throws {
        let keyPair = try RSAKeyPair()
        let subject = CSRSubject.appleDevelopment(name: "Envelope Test", userID: "ENV1", teamID: "TEAMENV")
        let pem = try CSRGenerator.generateCSRPEM(keyPair: keyPair, subject: subject)

        let plistPayload: [String: Any] = [
            "clientId": "XABBG36SBA",
            "protocolVersion": "QH65B2",
            "requestId": UUID().uuidString,
            "teamId": "TEAMENV",
            "csrContent": pem,
            "machineName": "GhostSign Workstation",
            "machineId": UUID().uuidString
        ]

        let xmlData = try PropertyListSerialization.data(fromPropertyList: plistPayload, format: .xml, options: 0)
        XCTAssertFalse(xmlData.isEmpty)

        // Read back
        let readDict = try PropertyListSerialization.propertyList(from: xmlData, options: [], format: nil) as? [String: Any]
        XCTAssertNotNil(readDict)
        let restoredPEM = readDict?["csrContent"] as? String
        XCTAssertEqual(restoredPEM, pem)

        // Verify the extracted PEM is still cryptographically valid
        XCTAssertTrue(CSRGenerator.verify(csrPEM: restoredPEM!))
    }

    func testOpenSSLVerificationIfAvailable() throws {
        guard FileManager.default.isExecutableFile(atPath: "/usr/bin/openssl") else {
            return
        }

        let keyPair = try RSAKeyPair()
        let subject = CSRSubject.appleDevelopment(
            name: "John Appleseed",
            userID: "JA12345",
            teamID: "TEAMAPP",
            teamName: "Appleseed Inc"
        )
        let (der, pem) = try CSRGenerator.generateCSR(keyPair: keyPair, subject: subject)

        let tempDir = FileManager.default.temporaryDirectory
        let pemPath = tempDir.appendingPathComponent("test_generated_csr.pem")
        let derPath = tempDir.appendingPathComponent("test_generated_csr.der")
        defer {
            try? FileManager.default.removeItem(at: pemPath)
            try? FileManager.default.removeItem(at: derPath)
        }

        try pem.write(to: pemPath, atomically: true, encoding: .utf8)
        try der.write(to: derPath)

        // Verify PEM with OpenSSL: openssl req -in csr.pem -text -noout -verify
        let pemProcess = Process()
        pemProcess.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        pemProcess.arguments = ["req", "-in", pemPath.path, "-text", "-noout", "-verify"]
        let pemPipe = Pipe()
        pemProcess.standardOutput = pemPipe
        pemProcess.standardError = pemPipe
        try pemProcess.run()
        pemProcess.waitUntilExit()
        XCTAssertEqual(pemProcess.terminationStatus, 0)
        let pemOutput = String(data: pemPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        XCTAssertTrue(pemOutput.contains("Certificate request self-signature verify OK"), "OpenSSL verify output: \(pemOutput)")

        // Verify DER with OpenSSL: openssl req -inform der -in csr.der -text -noout -verify
        let derProcess = Process()
        derProcess.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        derProcess.arguments = ["req", "-inform", "der", "-in", derPath.path, "-text", "-noout", "-verify"]
        let derPipe = Pipe()
        derProcess.standardOutput = derPipe
        derProcess.standardError = derPipe
        try derProcess.run()
        derProcess.waitUntilExit()
        XCTAssertEqual(derProcess.terminationStatus, 0)
        let derOutput = String(data: derPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        XCTAssertTrue(derOutput.contains("Certificate request self-signature verify OK"), "OpenSSL verify output: \(derOutput)")
    }
}
