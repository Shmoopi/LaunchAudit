import Foundation

public struct FolderActionScanner: PersistenceScanner {
    public let category = PersistenceCategory.folderActions
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        [PathUtilities.expandTilde("~/Library/Workflows/Applications/Folder Actions")]
    }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        var items: [PersistenceItem] = []

        // Check Folder Actions workflows directory
        let faDir = PathUtilities.expandTilde("~/Library/Workflows/Applications/Folder Actions")
        if PathUtilities.exists(faDir) {
            let workflows = PathUtilities.listFiles(in: faDir)
            for workflow in workflows {
                let name = (workflow as NSString).lastPathComponent
                let timestamps = PathUtilities.timestamps(for: workflow)

                items.append(PersistenceItem(
                    category: category,
                    name: name,
                    configPath: workflow,
                    isEnabled: true,
                    runContext: .triggered,
                    owner: .user(PathUtilities.currentUser),
                    timestamps: timestamps,
                    rawMetadata: ["Type": .string("Folder Action")]
                ))
            }
        }

        // Check if Folder Actions Dispatcher is enabled
        let dispatcherPlist = PathUtilities.expandTilde(
            "~/Library/Preferences/com.apple.FolderActionsDispatcher.plist"
        )
        if PathUtilities.exists(dispatcherPlist) {
            if let dict = try? PlistParser().parse(at: dispatcherPlist) {
                let enabled = dict["folderActionsEnabled"] as? Bool ?? false
                if enabled {
                    items.append(PersistenceItem(
                        category: category,
                        name: "Folder Actions Dispatcher (enabled)",
                        configPath: dispatcherPlist,
                        isEnabled: true,
                        runContext: .triggered,
                        owner: .user(PathUtilities.currentUser),
                        rawMetadata: PlistParser().toMetadata(dict)
                    ))
                }
            }
        }

        return items
    }
}
