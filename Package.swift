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
        .executable(
            name: "ConsentBusDemo",
            targets: ["ConsentBusDemo"]
        ),
    ],
    targets: [
        .target(
            name: "ConsentBus",
            dependencies: []
        ),
        .executableTarget(
            name: "ConsentBusDemo",
            dependencies: ["ConsentBus"]
        ),
        .testTarget(
            name: "ConsentBusTests",
            dependencies: ["ConsentBus"]
        ),
    ]
)
