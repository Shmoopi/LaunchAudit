import Foundation

public struct ScriptingAdditionScanner: PersistenceScanner {
    public let category = PersistenceCategory.scriptingAdditions
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        [
            "/Library/ScriptingAdditions",
            PathUtilities.expandTilde("~/Library/ScriptingAdditions")
        ]
    }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        let scanner = DirectoryBundleScanner()
        var allItems: [PersistenceItem] = []

        let (sysItems, _) = scanner.scanBundles(
            in: ["/Library/ScriptingAdditions"],
            bundleExtension: "osax",
            category: category,
            owner: .system
        )
        allItems.append(contentsOf: sysItems)

        let userDir = PathUtilities.expandTilde("~/Library/ScriptingAdditions")
        let (userItems, _) = scanner.scanBundles(
            in: [userDir],
            bundleExtension: "osax",
            category: category,
            owner: .user(PathUtilities.currentUser)
        )
        allItems.append(contentsOf: userItems)

        return allItems
    }
}
