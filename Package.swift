// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Ghost-Sign",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "GhostSign",
            targets: ["GhostSign"]
        ),
    ],
    dependencies: [
        .package(path: "../ghost-code"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .target(
            name: "GhostSign",
            dependencies: [
                .product(name: "GhostCode", package: "ghost-code"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
            ]
        ),
        .testTarget(
            name: "GhostSignTests",
            dependencies: ["GhostSign"]
        ),
    ]
)
