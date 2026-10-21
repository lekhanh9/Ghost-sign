# ghost-sign

A lightweight, zero-Keychain Apple code signing and developer portal orchestration engine for Swift on iOS, macOS, and Linux.

## Key Architecture & Features

- **Strict Zero-Keychain Design**: Completely eliminates Apple Keychain APIs (`SecItemAdd`, `SecItemCopyMatching`, `SecIdentity`, `SecKeyCreateSignature`). All private keys and certificates are held and manipulated in memory (`Data`).
- **Encrypted Sandbox File Storage**: Follows the SideStore sandbox architecture (referencing SideStore Issue #1647). Identities and provisioning profiles are stored in the app's sandboxed `Documents/GhostSign/` directory, encrypted at rest using AES-GCM via `swift-crypto`.
- **Universal Dual Format Support**: Full support for both DER (`*.der`, `*.cer`) and PEM (`*.pem`, `*.crt`, `*.key`) formats for RSA private keys, certificates, CSRs, and provisioning profiles.
- **In-Memory RSA Key Pair & PKCS#10 CSR Generation**:
  - 2048-bit RSA key generation with PKCS#1 and PKCS#8 import/export (`RSAKeyPair`).
  - RFC 2986 compliant PKCS#10 Certificate Signing Request generator with hardened DER length parsing resistant to integer overflow attacks (`CSRGenerator`).
- **Apple Developer Services 2 (`QH65B2`) Client**:
  - Full async client (`DeveloperPortalClient`) supporting all 11 Developer Services actions:
    - `listTeams`
    - `listDevices` & `addDevice`
    - `listAppIds` & `addAppId`
    - `listAllDevelopmentCerts` & `submitDevelopmentCSR`
    - `listProvisioningProfiles`, `createProvisioningProfile`, & `downloadTeamProvisioningProfile`
  - Strongly typed Apple error responses (`DeveloperPortalError`).
  - Binary certificate (`.cer`) and provisioning profile (`.mobileprovision`) extraction directly into memory (`Data`).
- **In-Memory PKCS#12 Engine**:
  - `PKCS12Exporter`: Exports in-memory certificates and private keys into standard `.p12` archives using PBES2 encryption (AES-256-CBC + PBKDF2-HMAC-SHA256) or unencrypted KeyBags.
  - `PKCS12Parser`: Parses and decrypts PKCS#12 bundles in memory without calling system Keychain routines.
  - `PEMDERCodec`: Bidirectional converter between DER and PEM formats.
- **BridgeSigner Integration**:
  - Seamlessly bridges developer portal assets and raw in-memory keys/certificates to `GhostCode` (`GhostSigner`) for Mach-O signing, code directory hashing, bundle sealing, and CMS signature embedding.

## Installation

Add `ghost-sign` as a dependency in your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/lekhanh9/ghost-sign.git", branch: "main")
]
```

## Quick Start

### 1. Generate RSA 2048-bit Key & CSR

```swift
import GhostSign

// Generate an in-memory 2048-bit RSA key pair
let keyPair = try RSAKeyPair.generate(keySizeInBits: 2048)

// Create an RFC 2986 compliant PKCS#10 CSR
let subject = CSRSubject(
    commonName: "Apple Development: user@example.com",
    organization: "Personal Team",
    country: "US"
)
let csrData = try CSRGenerator.generateCSR(subject: subject, keyPair: keyPair)
```

### 2. Request Certificate from Apple Developer Portal

```swift
import GhostSign

let portalClient = DeveloperPortalClient(
    sessionToken: "gs-token-from-auth",
    dsid: "apple-dsid"
)

// List teams and select team
let teams = try await portalClient.listTeams()
guard let team = teams.first else { return }

// Submit CSR to Apple
let certRecord = try await portalClient.submitDevelopmentCSR(
    teamId: team.teamId,
    csrDER: csrData
)

// Extract raw certificate DER bytes
let certDER = certRecord.certificateData
let privateKeyDER = try keyPair.exportPrivateKeyPKCS8DER()
```

### 3. Store Identity Securely in Sandbox

```swift
let storage = try FileStorageManager(encryptAtRest: true)

let identity = RawIdentity(
    certificateDER: certDER,
    privateKeyDER: privateKeyDER
)

try storage.saveIdentity(identity, name: "DeveloperIdentity")
```

### 4. Sign Application Bundle via BridgeSigner

```swift
import GhostSign
import GhostCode
import Foundation

let bundleURL = URL(fileURLWithPath: "/path/to/MyApp.app")

// Sign bundle using raw in-memory developer portal assets
try await BridgeSigner.signBundleWithDeveloperPortalAssets(
    bundleURL: bundleURL,
    portalClient: portalClient,
    teamId: team.teamId,
    privateKeyDER: privateKeyDER,
    certRecord: certRecord,
    profileId: "profile-id-here"
)
```

## Running Tests

```bash
swift test
```

All 67 test cases across CSR generation, Developer Portal mock protocols, sandbox storage, PKCS#12 export/import, and RSA key pairs run and pass on Linux and Apple platforms.
