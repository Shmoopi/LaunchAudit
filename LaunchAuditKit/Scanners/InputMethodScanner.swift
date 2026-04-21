import Foundation

public struct InputMethodScanner: PersistenceScanner {
    public let category = PersistenceCategory.inputMethods
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        [
            "/Library/Input Methods",
            PathUtilities.expandTilde("~/Library/Input Methods"),
            "/Library/InputManagers",
            PathUtilities.expandTilde("~/Library/InputManagers")
        ]
    }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        let bundleScanner = DirectoryBundleScanner()
        var allItems: [PersistenceItem] = []

        // Input Methods (.app bundles in Input Methods directories)
        for dir in ["/Library/Input Methods",
                    PathUtilities.expandTilde("~/Library/Input Methods")] {
            guard PathUtilities.exists(dir) else { continue }
            let owner: ItemOwner = dir.hasPrefix("/Library") ? .system : .user(PathUtilities.currentUser)
            let (items, _) = bundleScanner.scanBundles(
                in: [dir],
                bundleExtension: "app",
                category: category,
                owner: owner
            )
            allItems.append(contentsOf: items)
        }

        // InputManagers (deprecated, known attack vector)
        for dir in ["/Library/InputManagers",
                    PathUtilities.expandTilde("~/Library/InputManagers")] {
            guard PathUtilities.exists(dir) else { continue }
            let owner: ItemOwner = dir.hasPrefix("/Library") ? .system : .user(PathUtilities.currentUser)
            let subdirs = PathUtilities.listDirectories(in: dir)
            for subdir in subdirs {
                let name = (subdir as NSString).lastPathComponent
                let timestamps = PathUtilities.timestamps(for: subdir)
                allItems.append(PersistenceItem(
                    category: category,
                    name: name,
                    configPath: subdir,
                    isEnabled: true,
                    runContext: .login,
                    owner: owner,
                    riskLevel: .high,
                    riskReasons: ["Uses deprecated InputManagers mechanism — known malware vector"],
                    timestamps: timestamps,
                    rawMetadata: ["Type": .string("InputManager"), "Deprecated": .bool(true)]
                ))
            }
        }

        return allItems
    }
}
