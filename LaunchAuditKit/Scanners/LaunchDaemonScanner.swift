import Foundation

public struct LaunchDaemonScanner: PersistenceScanner {
    public let category = PersistenceCategory.launchDaemons
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        [
            "/System/Library/LaunchDaemons",
            "/Library/LaunchDaemons"
        ]
    }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        let helper = DirectoryPlistScanner()
        var allItems: [PersistenceItem] = []
        var allErrors: [ScanError] = []

        // System daemons (Apple)
        let (sysItems, sysErrors) = helper.scanPlists(
            in: ["/System/Library/LaunchDaemons"],
            category: category,
            owner: .system,
            runContext: .boot
        )
        allItems.append(contentsOf: sysItems.map { item in
            var modified = item
            modified.riskLevel = .informational
            return modified
        })
        allErrors.append(contentsOf: sysErrors)

        // Third-party daemons
        let (libItems, libErrors) = helper.scanPlists(
            in: ["/Library/LaunchDaemons"],
            category: category,
            owner: .system,
            runContext: .boot
        )
        allItems.append(contentsOf: libItems)
        allErrors.append(contentsOf: libErrors)

        return allItems
    }
}
