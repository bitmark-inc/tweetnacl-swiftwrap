// swift-tools-version:4.0
import PackageDescription

let package = Package(name: "TweetNacl", products: [.library(name: "TweetNacl", targets: ["TweetNacl"])],
            targets: [
                .target(name: "CTweetNacl"),
                .target(name: "TweetNacl", dependencies: ["CTweetNacl"]),
                .testTarget(name: "TweetNaclTests", dependencies: ["TweetNacl"]),
            ],
            swiftLanguageVersions: [4])