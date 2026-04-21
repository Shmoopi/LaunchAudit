import Foundation

public struct LaunchAgentScanner: PersistenceScanner {
    public let category = PersistenceCategory.launchAgents
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        [
            "/System/Library/LaunchAgents",
            "/Library/LaunchAgents",
            PathUtilities.expandTilde("~/Library/LaunchAgents")
        ]
    }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        let helper = DirectoryPlistScanner()
        var allItems: [PersistenceItem] = []

        // System agents (Apple)
        let (sysItems, _) = helper.scanPlists(
            in: ["/System/Library/LaunchAgents"],
            category: category,
            owner: .system,
            runContext: .login
        )
        allItems.append(contentsOf: sysItems.map { item in
            var modified = item
            modified.riskLevel = .informational
            return modified
        })

        // System-wide third-party agents
        let (libItems, _) = helper.scanPlists(
            in: ["/Library/LaunchAgents"],
            category: category,
            owner: .system,
            runContext: .login
        )
        allItems.append(contentsOf: libItems)

        // Per-user agents
        let userDir = PathUtilities.expandTilde("~/Library/LaunchAgents")
        let (userItems, _) = helper.scanPlists(
            in: [userDir],
            category: category,
            owner: .user(PathUtilities.currentUser),
            runContext: .login
        )
        allItems.append(contentsOf: userItems)

        return allItems
    }
}
