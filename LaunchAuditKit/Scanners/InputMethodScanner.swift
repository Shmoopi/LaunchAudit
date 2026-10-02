import Foundation

public struct InputMethodScanner: PersistenceScanner {
    public let category = PersistenceCategory.inputMethods
    public let requiresPrivilege = false

    private let inputMethodSystemDirs = ["/Library/Input Methods"]
    private let inputMethodUserSuffix = "Library/Input Methods"
    private let inputManagerSystemDirs = ["/Library/InputManagers"]
    private let inputManagerUserSuffix = "Library/InputManagers"

    public var scanPaths: [String] {
        var paths = inputMethodSystemDirs + inputManagerSystemDirs
        for (_, home) in PathUtilities.scannableHomeDirectories() {
            paths.append((home as NSString).appendingPathComponent(inputMethodUserSuffix))
            paths.append((home as NSString).appendingPathComponent(inputManagerUserSuffix))
        }
        return paths
    }

    public init() {}

    public func scan() async throws -> ScanOutcome {
        let bundleScanner = DirectoryBundleScanner()
        var outcome = ScanOutcome()

        // Input methods are .app bundles.
        outcome.merge(bundleScanner.scanBundles(
            in: inputMethodSystemDirs,
            bundleExtension: "app",
            category: category,
            owner: .system,
            runContext: .login
        ))
        for (user, home) in PathUtilities.scannableHomeDirectories() {
            let dir = (home as NSString).appendingPathComponent(inputMethodUserSuffix)
            outcome.merge(bundleScanner.scanBundles(
                in: [dir],
                bundleExtension: "app",
                category: category,
                owner: .user(user),
                runContext: .login
            ))
        }

        // InputManagers: removed from macOS long ago and a classic injection
        // vector, so any hit is critical. `RiskClassifier` keys the critical
        // escalation on the `Deprecated` metadata flag set below.
        var managerDirectories: [(String, ItemOwner)] =
            inputManagerSystemDirs.map { ($0, .system) }
        for (user, home) in PathUtilities.scannableHomeDirectories() {
            managerDirectories.append(
                ((home as NSString).appendingPathComponent(inputManagerUserSuffix), .user(user))
            )
        }

        for (directory, owner) in managerDirectories {
            let (subdirs, errors) = entries(in: directory, includeDirectories: true)
            outcome.errors += errors
            for subdir in subdirs where PathUtilities.isDirectory(subdir) {
                outcome.items.append(PersistenceItem(
                    category: category,
                    name: (subdir as NSString).lastPathComponent,
                    configPath: subdir,
                    isEnabled: true,
                    runContext: .login,
                    owner: owner,
                    riskLevel: .high,
                    riskReasons: [
                        "Uses the deprecated InputManagers mechanism — a known "
                            + "code-injection vector that modern macOS does not load",
                    ],
                    timestamps: PathUtilities.timestamps(for: subdir),
                    rawMetadata: [
                        "Type": .string("InputManager"),
                        "Deprecated": .bool(true),
                    ]
                ))
            }
        }

        return outcome
    }
}
