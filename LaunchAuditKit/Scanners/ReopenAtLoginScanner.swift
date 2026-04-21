import Foundation

public struct ReopenAtLoginScanner: PersistenceScanner {
    public let category = PersistenceCategory.reopenAtLogin
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        [PathUtilities.expandTilde("~/Library/Preferences/ByHost")]
    }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        var items: [PersistenceItem] = []

        // Check TALAppsToRelaunchAtLogin in loginwindow plist
        let byHostDir = PathUtilities.expandTilde("~/Library/Preferences/ByHost")
        let plists = PathUtilities.listFiles(in: byHostDir, withExtension: "plist")

        for plistPath in plists {
            let filename = (plistPath as NSString).lastPathComponent
            guard filename.hasPrefix("com.apple.loginwindow") else { continue }

            guard let dict = try? PlistParser().parse(at: plistPath) else { continue }

            if let talApps = dict["TALAppsToRelaunchAtLogin"] as? [[String: Any]] {
                for app in talApps {
                    let name = app["BundleID"] as? String
                        ?? app["Path"] as? String
                        ?? "Unknown"
                    let path = app["Path"] as? String
                    let bundleID = app["BundleID"] as? String

                    items.append(PersistenceItem(
                        category: category,
                        name: (name as NSString).lastPathComponent,
                        label: bundleID,
                        configPath: plistPath,
                        executablePath: path,
                        isEnabled: true,
                        runContext: .login,
                        owner: .user(PathUtilities.currentUser),
                        rawMetadata: PlistParser().toMetadata(app)
                    ))
                }
            }
        }

        // Check Saved Application State directories
        let savedStateDir = PathUtilities.expandTilde("~/Library/Saved Application State")
        if PathUtilities.exists(savedStateDir) {
            let stateDirs = PathUtilities.listDirectories(in: savedStateDir)
            for stateDir in stateDirs {
                let bundleID = (stateDir as NSString).lastPathComponent
                    .replacingOccurrences(of: ".savedState", with: "")
                let timestamps = PathUtilities.timestamps(for: stateDir)

                items.append(PersistenceItem(
                    category: category,
                    name: bundleID,
                    label: bundleID,
                    configPath: stateDir,
                    isEnabled: true,
                    runContext: .login,
                    owner: .user(PathUtilities.currentUser),
                    riskLevel: .informational,
                    timestamps: timestamps,
                    rawMetadata: ["Type": .string("Saved Application State")]
                ))
            }
        }

        return items
    }
}
