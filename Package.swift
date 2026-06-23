// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ConsentBus",
    platforms: [
        .iOS(.v16),
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "ConsentBus",
            targets: ["ConsentBus"]
        ),
    ],
    targets: [
        .target(
            name: "ConsentBus",
            dependencies: []
        ),
        .testTarget(
            name: "ConsentBusTests",
            dependencies: ["ConsentBus"]
        ),
    ]
)
