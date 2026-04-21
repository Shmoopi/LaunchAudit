import Foundation

public struct WidgetScanner: PersistenceScanner {
    public let category = PersistenceCategory.widgets
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        [
            "/Library/Widgets",
            PathUtilities.expandTilde("~/Library/Widgets")
        ]
    }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        let scanner = DirectoryBundleScanner()
        var allItems: [PersistenceItem] = []

        let (sysItems, _) = scanner.scanBundles(
            in: ["/Library/Widgets"],
            bundleExtension: "wdgt",
            category: category,
            owner: .system
        )
        allItems.append(contentsOf: sysItems)

        let userDir = PathUtilities.expandTilde("~/Library/Widgets")
        let (userItems, _) = scanner.scanBundles(
            in: [userDir],
            bundleExtension: "wdgt",
            category: category,
            owner: .user(PathUtilities.currentUser)
        )
        allItems.append(contentsOf: userItems)

        return allItems
    }
}
