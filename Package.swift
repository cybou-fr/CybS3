// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "CybS3",
    platforms: [
        .macOS(.v12),
    ],
    products: [
        .executable(name: "cybs3", targets: ["CybS3"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-crypto", from: "3.5.0"),
        .package(url: "https://github.com/swift-server/async-http-client", from: "1.21.0"),
        .package(url: "https://github.com/apple/swift-log", from: "1.5.0"),
        .package(url: "https://github.com/cybou-fr/SwiftBIP39.git", branch: "main"),
    ],
    targets: [
        .executableTarget(
            name: "CybS3",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "AsyncHTTPClient", package: "async-http-client"),
                .product(name: "Logging", package: "swift-log"),
                "SwiftBIP39",
            ]
        ),
    ]
)