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
    targets: [
        .target(
            name: "GhostSign"
        ),
        .testTarget(
            name: "GhostSignTests",
            dependencies: ["GhostSign"]
        ),
    ]
)
