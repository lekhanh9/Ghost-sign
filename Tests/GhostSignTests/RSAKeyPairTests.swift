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

    // MARK: - Adversarial Regression Tests (ASN.1 Overflow & Loose PEM Parsing)

    func testDERImportRejectsASN1LengthOverflowAttacks() {
        let vectors: [(name: String, data: Data)] = [
            ("8-byte negative overflow", Data([0x30, 0x88, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00])),
            ("5-byte excessive length", Data([0x30, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xBB])),
            ("8-byte Int64.max overflow", Data([0x30, 0x88, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x02])),
            ("Indefinite length", Data([0x30, 0x80, 0x02, 0x01, 0x00, 0x00, 0x00])),
            ("127-byte length octet", Data([0x30, 0xFF] + Array(repeating: UInt8(0x01), count: 127))),
            ("2GB excessive length", Data([0x30, 0x84, 0x7F, 0xFF, 0xFF, 0xFF, 0x00, 0x00]))
        ]

        for (name, data) in vectors {
            XCTAssertThrowsError(try RSAKeyPair(derRepresentation: data), "[\(name)] derRepresentation") { error in
                guard let keyError = error as? RSAKeyPairError, case .invalidDERFormat = keyError else {
                    XCTFail("[\(name)] Expected invalidDERFormat, got: \(error)")
                    return
                }
            }
            XCTAssertThrowsError(try RSAKeyPair(pkcs1DER: data), "[\(name)] pkcs1DER") { error in
                guard let keyError = error as? RSAKeyPairError, case .invalidDERFormat = keyError else {
                    XCTFail("[\(name)] Expected invalidDERFormat for pkcs1DER, got: \(error)")
                    return
                }
            }
            XCTAssertThrowsError(try RSAKeyPair(pkcs8DER: data), "[\(name)] pkcs8DER") { error in
                guard let keyError = error as? RSAKeyPairError, case .invalidDERFormat = keyError else {
                    XCTFail("[\(name)] Expected invalidDERFormat for pkcs8DER, got: \(error)")
                    return
                }
            }
        }
    }

    func testPEMParsingRejectsTruncatedPrivateKeyArmors() throws {
        let keyPair = try RSAKeyPair()
        let pkcs1PEM = keyPair.pkcs1PEM
        let pkcs8PEM = keyPair.pkcs8PEM

        // 1. Truncated PKCS#1: Remove closing delimiter completely
        let truncatedPKCS1 = pkcs1PEM.replacingOccurrences(of: "-----END RSA PRIVATE KEY-----", with: "")
        XCTAssertThrowsError(try RSAKeyPair(pemRepresentation: truncatedPKCS1)) { error in
            guard let keyError = error as? RSAKeyPairError, case .invalidPEMFormat = keyError else {
                XCTFail("Expected invalidPEMFormat for truncated PKCS#1 PEM, got: \(error)")
                return
            }
        }
        XCTAssertThrowsError(try RSAKeyPair(pkcs1PEM: truncatedPKCS1)) { error in
            guard let keyError = error as? RSAKeyPairError, case .invalidPEMFormat = keyError else {
                XCTFail("Expected invalidPEMFormat for truncated pkcs1PEM convenience init, got: \(error)")
                return
            }
        }

        // 2. Truncated PKCS#8: Remove closing delimiter completely
        let truncatedPKCS8 = pkcs8PEM.replacingOccurrences(of: "-----END PRIVATE KEY-----", with: "")
        XCTAssertThrowsError(try RSAKeyPair(pemRepresentation: truncatedPKCS8)) { error in
            guard let keyError = error as? RSAKeyPairError, case .invalidPEMFormat = keyError else {
                XCTFail("Expected invalidPEMFormat for truncated PKCS#8 PEM, got: \(error)")
                return
            }
        }
        XCTAssertThrowsError(try RSAKeyPair(pkcs8PEM: truncatedPKCS8)) { error in
            guard let keyError = error as? RSAKeyPairError, case .invalidPEMFormat = keyError else {
                XCTFail("Expected invalidPEMFormat for truncated pkcs8PEM convenience init, got: \(error)")
                return
            }
        }

        // 3. Truncated with trailing newlines and whitespace
        let truncatedWithWhitespace = truncatedPKCS1 + "\n\n   \n\t"
        XCTAssertThrowsError(try RSAKeyPair(pemRepresentation: truncatedWithWhitespace)) { error in
            guard let keyError = error as? RSAKeyPairError, case .invalidPEMFormat = keyError else {
                XCTFail("Expected invalidPEMFormat for truncated PEM with whitespace, got: \(error)")
                return
            }
        }

        // 4. PEM with only opening delimiter
        let onlyOpeningPKCS1 = "-----BEGIN RSA PRIVATE KEY-----\n"
        XCTAssertThrowsError(try RSAKeyPair(pemRepresentation: onlyOpeningPKCS1)) { error in
            guard let keyError = error as? RSAKeyPairError, case .invalidPEMFormat = keyError else {
                XCTFail("Expected invalidPEMFormat for only-opening delimiter, got: \(error)")
                return
            }
        }

        let onlyOpeningPKCS8 = "-----BEGIN PRIVATE KEY-----\n"
        XCTAssertThrowsError(try RSAKeyPair(pemRepresentation: onlyOpeningPKCS8)) { error in
            guard let keyError = error as? RSAKeyPairError, case .invalidPEMFormat = keyError else {
                XCTFail("Expected invalidPEMFormat for only-opening PKCS#8 delimiter, got: \(error)")
                return
            }
        }
    }

    func testPEMParsingRejectsMismatchedArmorDelimiters() throws {
        let keyPair = try RSAKeyPair()
        let pkcs1PEM = keyPair.pkcs1PEM
        let pkcs8PEM = keyPair.pkcs8PEM

        // 1. BEGIN RSA PRIVATE KEY paired with END CERTIFICATE
        let p1MismatchedCert = pkcs1PEM.replacingOccurrences(
            of: "-----END RSA PRIVATE KEY-----",
            with: "-----END CERTIFICATE-----"
        )
        XCTAssertThrowsError(try RSAKeyPair(pemRepresentation: p1MismatchedCert)) { error in
            guard let keyError = error as? RSAKeyPairError, case .invalidPEMFormat = keyError else {
                XCTFail("Expected invalidPEMFormat for RSA KEY paired with CERTIFICATE, got: \(error)")
                return
            }
        }

        // 2. BEGIN RSA PRIVATE KEY paired with END PRIVATE KEY (PKCS#1 header with PKCS#8 footer)
        let p1MismatchedPKCS8 = pkcs1PEM.replacingOccurrences(
            of: "-----END RSA PRIVATE KEY-----",
            with: "-----END PRIVATE KEY-----"
        )
        XCTAssertThrowsError(try RSAKeyPair(pemRepresentation: p1MismatchedPKCS8)) { error in
            guard let keyError = error as? RSAKeyPairError, case .invalidPEMFormat = keyError else {
                XCTFail("Expected invalidPEMFormat for PKCS#1 header with PKCS#8 footer, got: \(error)")
                return
            }
        }

        // 3. BEGIN PRIVATE KEY paired with END RSA PRIVATE KEY (PKCS#8 header with PKCS#1 footer)
        let p8MismatchedPKCS1 = pkcs8PEM.replacingOccurrences(
            of: "-----END PRIVATE KEY-----",
            with: "-----END RSA PRIVATE KEY-----"
        )
        XCTAssertThrowsError(try RSAKeyPair(pemRepresentation: p8MismatchedPKCS1)) { error in
            guard let keyError = error as? RSAKeyPairError, case .invalidPEMFormat = keyError else {
                XCTFail("Expected invalidPEMFormat for PKCS#8 header with PKCS#1 footer, got: \(error)")
                return
            }
        }

        // 4. BEGIN PRIVATE KEY paired with END CERTIFICATE
        let p8MismatchedCert = pkcs8PEM.replacingOccurrences(
            of: "-----END PRIVATE KEY-----",
            with: "-----END CERTIFICATE-----"
        )
        XCTAssertThrowsError(try RSAKeyPair(pemRepresentation: p8MismatchedCert)) { error in
            guard let keyError = error as? RSAKeyPairError, case .invalidPEMFormat = keyError else {
                XCTFail("Expected invalidPEMFormat for PRIVATE KEY paired with CERTIFICATE, got: \(error)")
                return
            }
        }

        // 5. BEGIN RSA PRIVATE KEY paired with END PUBLIC KEY
        let p1MismatchedPubKey = pkcs1PEM.replacingOccurrences(
            of: "-----END RSA PRIVATE KEY-----",
            with: "-----END PUBLIC KEY-----"
        )
        XCTAssertThrowsError(try RSAKeyPair(pemRepresentation: p1MismatchedPubKey)) { error in
            guard let keyError = error as? RSAKeyPairError, case .invalidPEMFormat = keyError else {
                XCTFail("Expected invalidPEMFormat for RSA KEY paired with PUBLIC KEY, got: \(error)")
                return
            }
        }

        // 6. BEGIN RSA PRIVATE KEY paired with END EC PRIVATE KEY
        let p1MismatchedEC = pkcs1PEM.replacingOccurrences(
            of: "-----END RSA PRIVATE KEY-----",
            with: "-----END EC PRIVATE KEY-----"
        )
        XCTAssertThrowsError(try RSAKeyPair(pemRepresentation: p1MismatchedEC)) { error in
            guard let keyError = error as? RSAKeyPairError, case .invalidPEMFormat = keyError else {
                XCTFail("Expected invalidPEMFormat for RSA KEY paired with EC KEY, got: \(error)")
                return
            }
        }
    }

    func testPEMImportRejectsEmbeddedASN1LengthOverflow() {
        let maliciousDER = Data([0x30, 0x88, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00])
        let maliciousBase64 = maliciousDER.base64EncodedString()
        let maliciousPEM = "-----BEGIN RSA PRIVATE KEY-----\n\(maliciousBase64)\n-----END RSA PRIVATE KEY-----\n"

        XCTAssertThrowsError(try RSAKeyPair(pemRepresentation: maliciousPEM)) { error in
            guard let keyError = error as? RSAKeyPairError else {
                XCTFail("Expected RSAKeyPairError, got: \(error)")
                return
            }
            switch keyError {
            case .invalidDERFormat, .invalidPEMFormat:
                break
            default:
                XCTFail("Unexpected error: \(keyError)")
            }
        }
    }

    func testEmbeddedDelimiterInsideBlockThrows() throws {
        let keyPair = try RSAKeyPair()
        let pkcs1PEM = keyPair.pkcs1PEM

        // Embedded END CERTIFICATE inside block must not be swallowed into base64
        let embedded = pkcs1PEM.replacingOccurrences(
            of: "-----END RSA PRIVATE KEY-----",
            with: "-----END CERTIFICATE-----\n-----END RSA PRIVATE KEY-----"
        )
        XCTAssertThrowsError(try RSAKeyPair(pemRepresentation: embedded))
    }

    func testNestedBeginDelimiterThrows() throws {
        let keyPair = try RSAKeyPair()
        let pkcs1PEM = keyPair.pkcs1PEM

        let nested = pkcs1PEM.replacingOccurrences(
            of: "-----BEGIN RSA PRIVATE KEY-----",
            with: "-----BEGIN RSA PRIVATE KEY-----\n-----BEGIN RSA PRIVATE KEY-----"
        )
        XCTAssertThrowsError(try RSAKeyPair(pemRepresentation: nested))
    }
}
