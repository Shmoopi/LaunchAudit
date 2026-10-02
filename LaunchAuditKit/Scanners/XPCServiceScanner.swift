import Foundation

public struct XPCServiceScanner: PersistenceScanner {
    public let category = PersistenceCategory.xpcServices

    /// Everything read here is world-readable and no subprocess is involved.
    /// Declaring it privileged meant an unprivileged headless run skipped the
    /// category and reported a false "requires root" error for it.
    public let requiresPrivilege = false

    /// Where XPC services actually live.
    ///
    /// The previous list was `/Library/Apple/System/Library/XPCServices` and
    /// `/Library/Developer/XPCServices` — neither exists on a current system, so
    /// the scanner returned nothing unconditionally. Third-party XPC services are
    /// embedded in app and framework bundles.
    private let standaloneDirectories = [
        "/Library/Apple/System/Library/XPCServices",
        "/Library/Developer/XPCServices",
    ]

    /// Bundles whose `Contents/XPCServices` is worth walking. Deliberately
    /// top-level only — recursing every application directory is unbounded.
    private var applicationDirectories: [String] {
        var directories = ["/Applications", "/Applications/Utilities", "/Library/Frameworks"]
        for (_, home) in PathUtilities.scannableHomeDirectories() {
            directories.append((home as NSString).appendingPathComponent("Applications"))
        }
        return directories
    }

    public var scanPaths: [String] { standaloneDirectories + applicationDirectories }

    public init() {}

    public func scan() async throws -> ScanOutcome {
        let helper = DirectoryBundleScanner()
        var outcome = ScanOutcome()

        outcome.merge(helper.scanBundles(
            in: standaloneDirectories,
            bundleExtension: "xpc",
            category: category,
            owner: .system,
            runContext: .onDemand
        ))

        // Embedded services: <bundle>/Contents/XPCServices/*.xpc
        for container in applicationDirectories {
            guard PathUtilities.exists(container) else { continue }
            let bundles = PathUtilities.listBundles(
                in: container, withExtensions: ["app", "framework"]
            )
            let embedded = bundles.map {
                ($0 as NSString).appendingPathComponent("Contents/XPCServices")
            }
            let owner: ItemOwner = {
                for (user, home) in PathUtilities.scannableHomeDirectories()
                where container.hasPrefix(home) {
                    return .user(user)
                }
                return .system
            }()
            outcome.merge(helper.scanBundles(
                in: embedded.filter { PathUtilities.exists($0) },
                bundleExtension: "xpc",
                category: category,
                owner: owner,
                runContext: .onDemand
            ))
        }

        return outcome
    }
}
