import Foundation

public struct AutomatorScanner: PersistenceScanner {
    public let category = PersistenceCategory.automatorWorkflows
    public let requiresPrivilege = false

    private let systemDirectories = ["/Library/Services"]
    private let userSuffix = "Library/Services"

    public var scanPaths: [String] {
        var paths = systemDirectories
        for (_, home) in PathUtilities.scannableHomeDirectories() {
            paths.append((home as NSString).appendingPathComponent(userSuffix))
        }
        return paths
    }

    public init() {}

    public func scan() async throws -> ScanOutcome {
        // Uses the shared bundle helper rather than a hand-rolled loop, which also
        // means Quick Actions now get a bundle identifier and an executable path,
        // so their signatures are actually verified.
        let helper = DirectoryBundleScanner()
        var outcome = ScanOutcome()

        outcome.merge(helper.scanBundles(
            in: systemDirectories,
            bundleExtension: "workflow",
            category: category,
            owner: .system,
            runContext: .onDemand
        ))

        for (user, home) in PathUtilities.scannableHomeDirectories() {
            let directory = (home as NSString).appendingPathComponent(userSuffix)
            outcome.merge(helper.scanBundles(
                in: [directory],
                bundleExtension: "workflow",
                category: category,
                owner: .user(user),
                runContext: .onDemand
            ))
        }

        // Surface the action list — an Automator workflow's risk lives in which
        // actions it runs, and "Run Shell Script" is the one that matters.
        for index in outcome.items.indices {
            let path = outcome.items[index].configPath
            guard let path else { continue }
            let documentPath = (path as NSString)
                .appendingPathComponent("Contents/document.wflow")
            guard let dict = try? PlistParser().parse(at: documentPath) else { continue }

            var actionNames: [String] = []
            if let actions = dict["actions"] as? [[String: Any]] {
                for action in actions {
                    guard let spec = action["action"] as? [String: Any] else { continue }
                    if let name = spec["ActionName"] as? String { actionNames.append(name) }
                    else if let bundle = spec["ActionBundlePath"] as? String {
                        actionNames.append((bundle as NSString).lastPathComponent)
                    }
                }
            }
            guard !actionNames.isEmpty else { continue }

            outcome.items[index].rawMetadata["Actions"] =
                .array(actionNames.map { .string($0) })

            if actionNames.contains(where: {
                $0.localizedCaseInsensitiveContains("shell script")
                    || $0.localizedCaseInsensitiveContains("applescript")
                    || $0.localizedCaseInsensitiveContains("run javascript")
            }) {
                outcome.items[index].riskReasons.append(
                    "Workflow runs arbitrary code: \(actionNames.joined(separator: ", "))"
                )
                outcome.items[index].riskLevel = .medium
            }
        }

        return outcome
    }
}
