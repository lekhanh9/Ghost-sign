//
//  RSAKeyPair.swift
//  GhostSign
//
//  Created for Ghost-Sign Milestone 1.
//  In-memory 2048-bit RSA Key Pair management (Raw Crypto).
//  STRICT ARCHITECTURE DIRECTIVE: Never saved to Apple Keychain.
//

import Foundation
import Crypto
import _CryptoExtras

// Typealias for convenience so both _RSA.KeySize and _RSA.Signing.KeySize can be used
extension _RSA {
    public typealias KeySize = _RSA.Signing.KeySize
}

/// Strongly typed errors encountered during RSA key pair generation, import, or export.
public enum RSAKeyPairError: Error, LocalizedError, Equatable {
    case invalidKeySize(Int)
    case invalidPEMFormat(String)
    case invalidDERFormat(String)
    case underlyingCryptoError(String)

    public var errorDescription: String? {
        switch self {
        case .invalidKeySize(let size):
            return "RSA key size \(size) bits is invalid. Minimum key size is 2048 bits."
        case .invalidPEMFormat(let reason):
            return "Failed to parse RSA key from PEM string: \(reason)"
        case .invalidDERFormat(let reason):
            return "Failed to parse RSA key from DER data: \(reason)"
        case .underlyingCryptoError(let message):
            return "Underlying cryptographic error: \(message)"
        }
    }
}

/// A cryptographically secure 2048-bit (or larger) RSA key pair conforming to PKCS#1 and PKCS#8 standards.
public struct RSAKeyPair: Sendable {
    /// The backing private key.
    public let privateKey: _RSA.Signing.PrivateKey

    /// The associated public key.
    public let publicKey: _RSA.Signing.PublicKey

    /// Generates a new cryptographically secure RSA key pair of the specified key size.
    /// Default key size is 2048 bits as required by Apple Developer Services.
    public init(keySize: _RSA.Signing.KeySize = .bits2048) throws {
        guard keySize.bitCount >= 2048 else {
            throw RSAKeyPairError.invalidKeySize(keySize.bitCount)
        }
        do {
            let privKey = try _RSA.Signing.PrivateKey(keySize: keySize)
            self.privateKey = privKey
            self.publicKey = privKey.publicKey
        } catch let err as RSAKeyPairError {
            throw err
        } catch {
            throw RSAKeyPairError.underlyingCryptoError(error.localizedDescription)
        }
    }

    /// Initializes a key pair by wrapping an existing `_RSA.Signing.PrivateKey`.
    public init(privateKey: _RSA.Signing.PrivateKey) {
        self.privateKey = privateKey
        self.publicKey = privateKey.publicKey
    }

    /// Initializes a key pair from binary DER representation.
    /// Automatically detects and parses both PKCS#1 (RSAPrivateKey) and PKCS#8 (PrivateKeyInfo) DER formats.
    public init(derRepresentation: Data) throws {
        do {
            let privKey = try _RSA.Signing.PrivateKey(derRepresentation: derRepresentation)
            guard privKey.keySizeInBits >= 2048 else {
                throw RSAKeyPairError.invalidKeySize(privKey.keySizeInBits)
            }
            self.privateKey = privKey
            self.publicKey = privKey.publicKey
        } catch let err as RSAKeyPairError {
            throw err
        } catch {
            throw RSAKeyPairError.invalidDERFormat(error.localizedDescription)
        }
    }

    /// Initializes a key pair from ASCII PEM representation.
    /// Automatically detects and parses both PKCS#1 (`BEGIN RSA PRIVATE KEY`)
    /// and PKCS#8 (`BEGIN PRIVATE KEY`) formats.
    public init(pemRepresentation: String) throws {
        // 1. Extract base64 bytes between strict standard PEM armor markers
        let derData = try Self.extractDERFromPEM(pemRepresentation)
        do {
            let privKey = try _RSA.Signing.PrivateKey(derRepresentation: derData)
            guard privKey.keySizeInBits >= 2048 else {
                throw RSAKeyPairError.invalidKeySize(privKey.keySizeInBits)
            }
            self.privateKey = privKey
            self.publicKey = privKey.publicKey
        } catch let err as RSAKeyPairError {
            throw err
        } catch {
            throw RSAKeyPairError.invalidDERFormat(error.localizedDescription)
        }
    }

    /// Convenience initializer for PKCS#1 DER format.
    public init(pkcs1DER: Data) throws {
        try self.init(derRepresentation: pkcs1DER)
    }

    /// Convenience initializer for PKCS#8 DER format.
    public init(pkcs8DER: Data) throws {
        try self.init(derRepresentation: pkcs8DER)
    }

    /// Convenience initializer for PKCS#1 PEM format.
    public init(pkcs1PEM: String) throws {
        try self.init(pemRepresentation: pkcs1PEM)
    }

    /// Convenience initializer for PKCS#8 PEM format.
    public init(pkcs8PEM: String) throws {
        try self.init(pemRepresentation: pkcs8PEM)
    }

    // MARK: - Export Properties

    /// PKCS#1 RSAPrivateKey binary DER representation (RFC 3447).
    public var pkcs1DER: Data {
        privateKey.derRepresentation
    }

    /// PKCS#8 PrivateKeyInfo binary DER representation (RFC 5208).
    public var pkcs8DER: Data {
        privateKey.pkcs8DERRepresentation
    }

    /// PKCS#1 ASCII PEM armored string (`-----BEGIN RSA PRIVATE KEY-----`).
    public var pkcs1PEM: String {
        privateKey.pemRepresentation
    }

    /// PKCS#8 ASCII PEM armored string (`-----BEGIN PRIVATE KEY-----`).
    public var pkcs8PEM: String {
        privateKey.pkcs8PEMRepresentation
    }

    /// SubjectPublicKeyInfo (SPKI) binary DER representation (RFC 5280).
    public var publicKeyDER: Data {
        publicKey.derRepresentation
    }

    /// SubjectPublicKeyInfo ASCII PEM armored string (`-----BEGIN PUBLIC KEY-----`).
    public var publicKeyPEM: String {
        publicKey.pemRepresentation
    }

    /// PKCS#1 RSAPublicKey binary DER representation.
    public var publicKeyPKCS1DER: Data {
        publicKey.pkcs1DERRepresentation
    }

    /// PKCS#1 RSAPublicKey ASCII PEM armored string (`-----BEGIN RSA PUBLIC KEY-----`).
    public var publicKeyPKCS1PEM: String {
        publicKey.pkcs1PEMRepresentation
    }

    /// Size of the RSA modulus in bits (e.g. 2048).
    public var keySizeInBits: Int {
        privateKey.keySizeInBits
    }

    // MARK: - Helper Methods

    private static func extractDERFromPEM(_ pem: String) throws -> Data {
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
                    throw RSAKeyPairError.invalidPEMFormat("Nested or unclosed PEM delimiter before '\(trimmed)'")
                }
                guard trimmed.count > 16 else { continue }
                let tag = String(trimmed.dropFirst(11).dropLast(5))
                if tag == "RSA PRIVATE KEY" || tag == "PRIVATE KEY" {
                    inBlock = true
                    openedTag = tag
                    base64 = ""
                }
            } else if trimmed.hasPrefix("-----END ") && trimmed.hasSuffix("-----") {
                if inBlock {
                    guard trimmed.count > 14 else {
                        throw RSAKeyPairError.invalidPEMFormat("Malformed PEM closing delimiter '\(trimmed)'")
                    }
                    let endTag = String(trimmed.dropFirst(9).dropLast(5))
                    if endTag == openedTag {
                        inBlock = false
                        blockClosed = true
                        break
                    } else {
                        throw RSAKeyPairError.invalidPEMFormat("Mismatched PEM delimiters: opened with '-----BEGIN \(openedTag)-----' but closed with '\(trimmed)'")
                    }
                }
            } else if inBlock {
                if trimmed.hasPrefix("-----") {
                    throw RSAKeyPairError.invalidPEMFormat("Unexpected delimiter or armor header inside PEM block: '\(trimmed)'")
                }
                base64.append(trimmed)
            }
        }

        if inBlock && !blockClosed {
            throw RSAKeyPairError.invalidPEMFormat("Truncated PEM: missing closing delimiter '-----END \(openedTag)-----'")
        }

        guard blockClosed else {
            throw RSAKeyPairError.invalidPEMFormat("No valid PKCS#1 or PKCS#8 RSA private key found in PEM string")
        }

        guard !base64.isEmpty, let derData = Data(base64Encoded: base64, options: .ignoreUnknownCharacters) else {
            throw RSAKeyPairError.invalidPEMFormat("Invalid Base64 payload in RSA private key PEM block")
        }

        return derData
    }
}
