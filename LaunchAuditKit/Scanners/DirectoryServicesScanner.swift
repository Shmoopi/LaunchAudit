import Foundation

public struct DirectoryServicesScanner: PersistenceScanner {
    public let category = PersistenceCategory.directoryServicesPlugins
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        ["/Library/DirectoryServices/PlugIns"]
    }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        let scanner = DirectoryBundleScanner()
        let (items, _) = scanner.scanBundles(
            in: scanPaths,
            bundleExtension: "dsplug",
            category: category,
            owner: .system
        )
        return items
    }
}
