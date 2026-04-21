import Foundation

public struct AudioPluginScanner: PersistenceScanner {
    public let category = PersistenceCategory.audioPlugins
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        ["/Library/Audio/Plug-Ins/HAL"]
    }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        let scanner = DirectoryBundleScanner()
        let (items, _) = scanner.scanBundles(
            in: scanPaths,
            bundleExtension: "plugin",
            category: category,
            owner: .system
        )

        // Also check for .driver bundles
        let (driverItems, _) = scanner.scanBundles(
            in: scanPaths,
            bundleExtension: "driver",
            category: category,
            owner: .system
        )

        return items + driverItems
    }
}
