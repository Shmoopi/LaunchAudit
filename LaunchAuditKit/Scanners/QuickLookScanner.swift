import Foundation

public struct QuickLookScanner: PersistenceScanner {
    public let category = PersistenceCategory.quickLookGenerators
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        [
            "/Library/QuickLook",
            PathUtilities.expandTilde("~/Library/QuickLook")
        ]
    }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        let scanner = DirectoryBundleScanner()
        var allItems: [PersistenceItem] = []

        let (sysItems, _) = scanner.scanBundles(
            in: ["/Library/QuickLook"],
            bundleExtension: "qlgenerator",
            category: category,
            owner: .system
        )
        allItems.append(contentsOf: sysItems)

        let userDir = PathUtilities.expandTilde("~/Library/QuickLook")
        let (userItems, _) = scanner.scanBundles(
            in: [userDir],
            bundleExtension: "qlgenerator",
            category: category,
            owner: .user(PathUtilities.currentUser)
        )
        allItems.append(contentsOf: userItems)

        return allItems
    }
}
