// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "azula-vm",
    platforms: [.macOS(.v13)],
    products: [.executable(name: "azula-vm", targets: ["azula-vm"])],
    targets: [.executableTarget(name: "azula-vm", path: "Sources/azula-vm")]
)
