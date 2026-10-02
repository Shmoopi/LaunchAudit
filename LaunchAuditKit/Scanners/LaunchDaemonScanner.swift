import Foundation

public struct LaunchDaemonScanner: PersistenceScanner {
    public let category = PersistenceCategory.launchDaemons
    public let requiresPrivilege = false

    /// `/Library/Apple/System/Library/LaunchDaemons` is where Apple delivers
    /// out-of-band, updatable daemons — XProtect, MRT, XprotectFramework. It is
    /// **not** on the sealed system volume, so unlike `/System/Library` it is
    /// modifiable with root. Omitting it was a genuine blind spot.
    public var scanPaths: [String] {
        [
            "/System/Library/LaunchDaemons",
            "/Library/Apple/System/Library/LaunchDaemons",
            "/Library/LaunchDaemons",
        ]
    }

    public init() {}

    public func scan() async throws -> ScanOutcome {
        let helper = DirectoryPlistScanner()
        var outcome = ScanOutcome()

        for directory in scanPaths {
            // `.boot` is the load context: a LaunchDaemon with RunAtLoad runs at
            // system boot, not at login.
            outcome.merge(helper.scanPlists(
                in: [directory],
                category: category,
                owner: .system,
                loadContext: .boot
            ))
        }

        return outcome
    }
}
