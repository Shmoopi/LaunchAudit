import Foundation

public struct LaunchAgentScanner: PersistenceScanner {
    public let category = PersistenceCategory.launchAgents
    public let requiresPrivilege = false

    private var systemDirectories: [String] {
        [
            "/System/Library/LaunchAgents",
            "/Library/Apple/System/Library/LaunchAgents",
            "/Library/LaunchAgents",
        ]
    }

    public var scanPaths: [String] {
        var paths = systemDirectories
        for (_, home) in PathUtilities.scannableHomeDirectories() {
            paths.append((home as NSString).appendingPathComponent("Library/LaunchAgents"))
        }
        return paths
    }

    public init() {}

    public func scan() async throws -> ScanOutcome {
        let helper = DirectoryPlistScanner()
        var outcome = ScanOutcome()

        for directory in systemDirectories {
            outcome.merge(helper.scanPlists(
                in: [directory],
                category: category,
                owner: .system,
                loadContext: .login
            ))
        }

        // Every real account, not just the invoking one. Under `sudo` the
        // invoking user's home is root's, so scanning only that directory made a
        // privileged scan see *less* user data than an unprivileged one.
        for (user, home) in PathUtilities.scannableHomeDirectories() {
            let userDir = (home as NSString).appendingPathComponent("Library/LaunchAgents")
            outcome.merge(helper.scanPlists(
                in: [userDir],
                category: category,
                owner: .user(user),
                loadContext: .login
            ))
        }

        return outcome
    }
}
