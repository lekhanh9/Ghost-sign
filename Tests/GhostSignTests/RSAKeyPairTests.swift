//
//  RSAKeyPairTests.swift
//  GhostSignTests
//
//  Created for Ghost-Sign Milestone 1.
//

import XCTest
@testable import GhostSign
import Crypto
import _CryptoExtras

final class RSAKeyPairTests: XCTestCase {

    func testDefault2048BitKeyGeneration() throws {
        let keyPair = try RSAKeyPair()
        XCTAssertEqual(keyPair.keySizeInBits, 2048)
        XCTAssertFalse(keyPair.publicKeyDER.isEmpty)
        XCTAssertFalse(keyPair.pkcs1DER.isEmpty)
        XCTAssertFalse(keyPair.pkcs8DER.isEmpty)
        XCTAssertFalse(keyPair.pkcs1PEM.isEmpty)
        XCTAssertFalse(keyPair.pkcs8PEM.isEmpty)
        XCTAssertTrue(keyPair.publicKeyDER.count > 256)
    }

    func testPKCS1DERExportImportRoundTrip() throws {
        let original = try RSAKeyPair()
        let pkcs1Data = original.pkcs1DER

        // Re-import via general derRepresentation
        let importedGeneral = try RSAKeyPair(derRepresentation: pkcs1Data)
        XCTAssertEqual(importedGeneral.keySizeInBits, 2048)
        XCTAssertEqual(importedGeneral.publicKeyDER, original.publicKeyDER)

        // Re-import via convenience pkcs1DER init
        let importedPKCS1 = try RSAKeyPair(pkcs1DER: pkcs1Data)
        XCTAssertEqual(importedPKCS1.keySizeInBits, 2048)
        XCTAssertEqual(importedPKCS1.publicKeyDER, original.publicKeyDER)
    }

    func testPKCS8DERExportImportRoundTrip() throws {
        let original = try RSAKeyPair()
        let pkcs8Data = original.pkcs8DER

        // Re-import via general derRepresentation
        let importedGeneral = try RSAKeyPair(derRepresentation: pkcs8Data)
        XCTAssertEqual(importedGeneral.keySizeInBits, 2048)
        XCTAssertEqual(importedGeneral.publicKeyDER, original.publicKeyDER)

        // Re-import via convenience pkcs8DER init
        let importedPKCS8 = try RSAKeyPair(pkcs8DER: pkcs8Data)
        XCTAssertEqual(importedPKCS8.keySizeInBits, 2048)
        XCTAssertEqual(importedPKCS8.publicKeyDER, original.publicKeyDER)
    }

    func testPKCS1PEMExportImportRoundTrip() throws {
        let original = try RSAKeyPair()
        let pkcs1PEM = original.pkcs1PEM

        XCTAssertTrue(pkcs1PEM.contains("-----BEGIN RSA PRIVATE KEY-----"))
        XCTAssertTrue(pkcs1PEM.contains("-----END RSA PRIVATE KEY-----"))

        // Re-import via general pemRepresentation
        let importedGeneral = try RSAKeyPair(pemRepresentation: pkcs1PEM)
        XCTAssertEqual(importedGeneral.keySizeInBits, 2048)
        XCTAssertEqual(importedGeneral.publicKeyDER, original.publicKeyDER)

        // Re-import via convenience pkcs1PEM init
        let importedPKCS1 = try RSAKeyPair(pkcs1PEM: pkcs1PEM)
        XCTAssertEqual(importedPKCS1.keySizeInBits, 2048)
        XCTAssertEqual(importedPKCS1.publicKeyDER, original.publicKeyDER)
    }

    func testPKCS8PEMExportImportRoundTrip() throws {
        let original = try RSAKeyPair()
        let pkcs8PEM = original.pkcs8PEM

        XCTAssertTrue(pkcs8PEM.contains("-----BEGIN PRIVATE KEY-----"))
        XCTAssertTrue(pkcs8PEM.contains("-----END PRIVATE KEY-----"))

        // Re-import via general pemRepresentation
        let importedGeneral = try RSAKeyPair(pemRepresentation: pkcs8PEM)
        XCTAssertEqual(importedGeneral.keySizeInBits, 2048)
        XCTAssertEqual(importedGeneral.publicKeyDER, original.publicKeyDER)

        // Re-import via convenience pkcs8PEM init
        let importedPKCS8 = try RSAKeyPair(pkcs8PEM: pkcs8PEM)
        XCTAssertEqual(importedPKCS8.keySizeInBits, 2048)
        XCTAssertEqual(importedPKCS8.publicKeyDER, original.publicKeyDER)
    }

    func testPublicKeysExportFormats() throws {
        let keyPair = try RSAKeyPair()

        // SPKI DER & PEM
        let spkiDER = keyPair.publicKeyDER
        let spkiPEM = keyPair.publicKeyPEM
        XCTAssertFalse(spkiDER.isEmpty)
        XCTAssertTrue(spkiPEM.contains("-----BEGIN PUBLIC KEY-----"))
        XCTAssertTrue(spkiPEM.contains("-----END PUBLIC KEY-----"))

        // Reconstruct public key from SPKI DER
        let pubKeyFromDER = try _RSA.Signing.PublicKey(derRepresentation: spkiDER)
        XCTAssertEqual(pubKeyFromDER.derRepresentation, spkiDER)

        // Reconstruct public key from SPKI PEM
        let pubKeyFromPEM = try _RSA.Signing.PublicKey(pemRepresentation: spkiPEM)
        XCTAssertEqual(pubKeyFromPEM.derRepresentation, spkiDER)

        // PKCS#1 Public Key DER & PEM
        let pkcs1PubDER = keyPair.publicKeyPKCS1DER
        let pkcs1PubPEM = keyPair.publicKeyPKCS1PEM
        XCTAssertFalse(pkcs1PubDER.isEmpty)
        XCTAssertTrue(pkcs1PubPEM.contains("-----BEGIN RSA PUBLIC KEY-----"))
        XCTAssertTrue(pkcs1PubPEM.contains("-----END RSA PUBLIC KEY-----"))
    }

    func testSignAndVerify() throws {
        let keyPair = try RSAKeyPair()
        let testData = Data("GhostSign Apple Developer Services Test Payload".utf8)
        let digest = SHA256.hash(data: testData)

        let signature = try keyPair.privateKey.signature(for: digest, padding: .insecurePKCS1v1_5)
        XCTAssertEqual(signature.rawRepresentation.count, 256)

        let isValid = keyPair.publicKey.isValidSignature(signature, for: digest, padding: .insecurePKCS1v1_5)
        XCTAssertTrue(isValid)

        // Tampered data must fail
        let tamperedData = Data("Tampered Payload".utf8)
        let tamperedDigest = SHA256.hash(data: tamperedData)
        let isInvalid = keyPair.publicKey.isValidSignature(signature, for: tamperedDigest, padding: .insecurePKCS1v1_5)
        XCTAssertFalse(isInvalid)
    }

    func testInvalidDERImportThrows() {
        let corruptData = Data([0x01, 0x02, 0x03, 0x04])
        XCTAssertThrowsError(try RSAKeyPair(derRepresentation: corruptData)) { error in
            guard let keyError = error as? RSAKeyPairError else {
                XCTFail("Expected RSAKeyPairError but got: \(error)")
                return
            }
            guard case .invalidDERFormat = keyError else {
                XCTFail("Expected invalidDERFormat but got: \(keyError)")
                return
            }
        }
    }

    func testInvalidPEMImportThrows() {
        let corruptPEM = "Not a valid PEM string"
        XCTAssertThrowsError(try RSAKeyPair(pemRepresentation: corruptPEM)) { error in
            guard let keyError = error as? RSAKeyPairError else {
                XCTFail("Expected RSAKeyPairError but got: \(error)")
                return
            }
            guard case .invalidPEMFormat = keyError else {
                XCTFail("Expected invalidPEMFormat but got: \(keyError)")
                return
            }
        }
    }

    func testSendableConcurrency() async throws {
        let keyPair = try RSAKeyPair()
        let task = Task.detached { () -> Int in
            return keyPair.keySizeInBits
        }
        let size = await task.value
        XCTAssertEqual(size, 2048)
    }

    func testOpenSSLKeyCheckIfAvailable() throws {
        let keyPair = try RSAKeyPair()
        let tempDir = FileManager.default.temporaryDirectory
        let pkcs1Path = tempDir.appendingPathComponent("test_key_pkcs1.pem")
        let pkcs8Path = tempDir.appendingPathComponent("test_key_pkcs8.pem")
        defer {
            try? FileManager.default.removeItem(at: pkcs1Path)
            try? FileManager.default.removeItem(at: pkcs8Path)
        }

        try keyPair.pkcs1PEM.write(to: pkcs1Path, atomically: true, encoding: .utf8)
        try keyPair.pkcs8PEM.write(to: pkcs8Path, atomically: true, encoding: .utf8)

        // Check if openssl binary exists
        guard FileManager.default.isExecutableFile(atPath: "/usr/bin/openssl") else {
            return
        }

        // Check PKCS#1 PEM
        let p1Process = Process()
        p1Process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        p1Process.arguments = ["rsa", "-in", pkcs1Path.path, "-check", "-noout"]
        let p1Pipe = Pipe()
        p1Process.standardOutput = p1Pipe
        p1Process.standardError = p1Pipe
        try p1Process.run()
        p1Process.waitUntilExit()
        XCTAssertEqual(p1Process.terminationStatus, 0)
        let p1Output = String(data: p1Pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        XCTAssertTrue(p1Output.contains("RSA key ok"))

        // Check PKCS#8 PEM
        let p8Process = Process()
        p8Process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        p8Process.arguments = ["rsa", "-in", pkcs8Path.path, "-check", "-noout"]
        let p8Pipe = Pipe()
        p8Process.standardOutput = p8Pipe
        p8Process.standardError = p8Pipe
        try p8Process.run()
        p8Process.waitUntilExit()
        XCTAssertEqual(p8Process.terminationStatus, 0)
        let p8Output = String(data: p8Pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        XCTAssertTrue(p8Output.contains("RSA key ok"))
    }

    func testTruncatedPEMThrows() throws {
        let keyPair = try RSAKeyPair()
        let pkcs1PEM = keyPair.pkcs1PEM

        let truncated = pkcs1PEM.replacingOccurrences(of: "-----END RSA PRIVATE KEY-----", with: "")
        XCTAssertThrowsError(try RSAKeyPair(pemRepresentation: truncated))
    }

    func testMismatchedPEMArmorsThrows() throws {
        let keyPair = try RSAKeyPair()
        let pkcs1PEM = keyPair.pkcs1PEM

        let mismatched = pkcs1PEM.replacingOccurrences(of: "-----END RSA PRIVATE KEY-----", with: "-----END CERTIFICATE-----")
        XCTAssertThrowsError(try RSAKeyPair(pemRepresentation: mismatched))
    }
}
