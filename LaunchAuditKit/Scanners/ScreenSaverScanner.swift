import Foundation

public struct ScreenSaverScanner: PersistenceScanner {
    public let category = PersistenceCategory.screenSavers
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        [
            "/Library/Screen Savers",
            PathUtilities.expandTilde("~/Library/Screen Savers")
        ]
    }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        let scanner = DirectoryBundleScanner()
        var allItems: [PersistenceItem] = []

        let (sysItems, _) = scanner.scanBundles(
            in: ["/Library/Screen Savers"],
            bundleExtension: "saver",
            category: category,
            owner: .system
        )
        allItems.append(contentsOf: sysItems)

        let userDir = PathUtilities.expandTilde("~/Library/Screen Savers")
        let (userItems, _) = scanner.scanBundles(
            in: [userDir],
            bundleExtension: "saver",
            category: category,
            owner: .user(PathUtilities.currentUser)
        )
        allItems.append(contentsOf: userItems)

        return allItems
    }
}
