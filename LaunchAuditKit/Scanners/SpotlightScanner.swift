import Foundation

public struct SpotlightScanner: PersistenceScanner {
    public let category = PersistenceCategory.spotlightImporters
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        [
            "/Library/Spotlight",
            PathUtilities.expandTilde("~/Library/Spotlight")
        ]
    }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        let scanner = DirectoryBundleScanner()
        var allItems: [PersistenceItem] = []

        let (sysItems, _) = scanner.scanBundles(
            in: ["/Library/Spotlight"],
            bundleExtension: "mdimporter",
            category: category,
            owner: .system
        )
        allItems.append(contentsOf: sysItems)

        let userDir = PathUtilities.expandTilde("~/Library/Spotlight")
        let (userItems, _) = scanner.scanBundles(
            in: [userDir],
            bundleExtension: "mdimporter",
            category: category,
            owner: .user(PathUtilities.currentUser)
        )
        allItems.append(contentsOf: userItems)

        return allItems
    }
}
