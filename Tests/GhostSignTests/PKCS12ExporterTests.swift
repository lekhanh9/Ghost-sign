//
//  PKCS12ExporterTests.swift
//  GhostSignTests
//
//  Created for Ghost-Sign Milestone 3.
//

import XCTest
@testable import GhostSign
import Foundation

final class PKCS12ExporterTests: XCTestCase {

    func testExportUnencryptedPKCS12AndRoundTripExtract() throws {
        let keyPair = try RSAKeyPair()
        let fakeCertDER = Data([0x30, 0x82, 0x01, 0x20, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x55, 0x04, 0x03])

        let p12Data = try PKCS12Exporter.export(
            certificateDER: fakeCertDER,
            privateKeyDER: keyPair.pkcs8DER,
            password: "",
            friendlyName: "Apple Development: Test User"
        )
        XCTAssertFalse(p12Data.isEmpty)
        XCTAssertEqual(p12Data[0], 0x30) // ASN.1 SEQUENCE

        // Extract using PKCS12Parser purely in memory
        let identity = try PKCS12Parser.extract(p12Data: p12Data, password: "")
        XCTAssertEqual(identity.certificateDER, fakeCertDER)
        XCTAssertEqual(identity.privateKeyDER, keyPair.pkcs8DER)
    }

    func testExportEncryptedPKCS12WithPasswordAndRoundTripExtract() throws {
        let keyPair = try RSAKeyPair()
        let fakeCertDER = Data([0x30, 0x82, 0x01, 0x35, 0x02, 0x01, 0x01, 0x05, 0x00])
        let password = "SuperSecretPassword123!"

        let p12Data = try PKCS12Exporter.export(
            certificateDER: fakeCertDER,
            privateKeyDER: keyPair.pkcs8DER,
            password: password,
            friendlyName: "GhostSign Development"
        )
        XCTAssertFalse(p12Data.isEmpty)

        // Decrypt with correct password
        let identity = try PKCS12Parser.extract(p12Data: p12Data, password: password)
        XCTAssertEqual(identity.certificateDER, fakeCertDER)
        XCTAssertEqual(identity.privateKeyDER, keyPair.pkcs8DER)

        // Decrypt with incorrect password must fail
        XCTAssertThrowsError(try PKCS12Parser.extract(p12Data: p12Data, password: "WrongPassword!"))
    }

    func testOpenSSLVerificationOfExportedPKCS12IfAvailable() throws {
        let opensslURL = URL(fileURLWithPath: "/usr/bin/openssl")
        guard FileManager.default.isExecutableFile(atPath: opensslURL.path) else { return }

        let keyPair = try RSAKeyPair()
        // Build a minimal self-signed or valid ASN.1 X.509 structure for OpenSSL parser
        let fakeCertDER = Data([
            0x30, 0x30,
            0x30, 0x14, 0x02, 0x01, 0x01, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x02, 0x43, 0x4E,
            0x30, 0x18, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x07, 0x00, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01
        ])
        let password = "TestPassword123"

        let p12Data = try PKCS12Exporter.export(
            certificateDER: fakeCertDER,
            privateKeyDER: keyPair.pkcs8DER,
            password: password,
            friendlyName: "Test Cert"
        )

        let tempURL = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".p12")
        defer { try? FileManager.default.removeItem(at: tempURL) }
        try p12Data.write(to: tempURL)

        let process = Process()
        process.executableURL = opensslURL
        process.arguments = ["pkcs12", "-in", tempURL.path, "-passin", "pass:\(password)", "-nodes", "-nocerts", "-noout"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        process.waitUntilExit()

        XCTAssertEqual(process.terminationStatus, 0, "OpenSSL failed to parse exported PKCS#12: \(String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "")")
    }

    func testPEMDERCodecRoundTrips() throws {
        let der = Data([0x30, 0x05, 0x02, 0x01, 0x01, 0x00, 0x00])

        let pem = PEMDERCodec.derToPEM(der: der, type: .certificate)
        XCTAssertTrue(pem.contains("-----BEGIN CERTIFICATE-----"))
        XCTAssertTrue(pem.contains("-----END CERTIFICATE-----"))

        let backToDER = PEMDERCodec.pemToDER(pem, expectedType: .certificate)
        XCTAssertEqual(backToDER, der)

        let normalizedFromPEM = PEMDERCodec.normalizeToDER(Data(pem.utf8))
        XCTAssertEqual(normalizedFromPEM, der)

        let normalizedFromDER = PEMDERCodec.normalizeToDER(der)
        XCTAssertEqual(normalizedFromDER, der)
    }
}
