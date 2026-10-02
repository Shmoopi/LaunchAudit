import Foundation

public struct DockTilePluginScanner: PersistenceScanner {
    public let category = PersistenceCategory.dockTilePlugins
    public let requiresPrivilege = false

    /// `/Applications/Utilities`, `/System/Applications` and each user's
    /// `~/Applications` were all missed by scanning only `/Applications`.
    private var applicationDirectories: [String] {
        var directories = [
            "/Applications",
            "/Applications/Utilities",
            "/System/Applications",
            "/System/Applications/Utilities",
        ]
        for (_, home) in PathUtilities.scannableHomeDirectories() {
            directories.append((home as NSString).appendingPathComponent("Applications"))
        }
        return directories
    }

    public var scanPaths: [String] { applicationDirectories }

    public init() {}

    public func scan() async throws -> ScanOutcome {
        var outcome = ScanOutcome()

        for container in applicationDirectories {
            guard PathUtilities.exists(container) else { continue }

            // Owner follows the location rather than being hardcoded `.system`,
            // which drives the root-vs-user determination in the risk model.
            let owner: ItemOwner = {
                for (user, home) in PathUtilities.scannableHomeDirectories()
                where container.hasPrefix(home) {
                    return .user(user)
                }
                return .system
            }()

            for appPath in PathUtilities.listBundles(in: container, withExtension: "app") {
                let infoPlistPath = (appPath as NSString)
                    .appendingPathComponent("Contents/Info.plist")
                guard PathUtilities.exists(infoPlistPath) else { continue }

                let dict: [String: Any]
                do {
                    dict = try PlistParser().parse(at: infoPlistPath)
                } catch {
                    outcome.errors.append(scanError(error, path: infoPlistPath))
                    continue
                }
                guard let dockTilePlugin = dict["NSDockTilePlugIn"] as? String else { continue }

                let appName = ((appPath as NSString).lastPathComponent as NSString)
                    .deletingPathExtension
                let pluginPath = (appPath as NSString)
                    .appendingPathComponent("Contents/PlugIns/\(dockTilePlugin)")

                // Resolve the binary inside the plugin bundle so it is verified.
                var executablePath = pluginPath
                let pluginInfo = (pluginPath as NSString)
                    .appendingPathComponent("Contents/Info.plist")
                if let pluginDict = try? PlistParser().parse(at: pluginInfo),
                   let execName = pluginDict["CFBundleExecutable"] as? String {
                    executablePath = (pluginPath as NSString)
                        .appendingPathComponent("Contents/MacOS/\(execName)")
                }

                var item = PersistenceItem(
                    category: category,
                    name: "\(appName) Dock Tile Plugin",
                    label: dict["CFBundleIdentifier"] as? String,
                    configPath: appPath,
                    executablePath: executablePath,
                    isEnabled: true,
                    runContext: .onDemand,
                    owner: owner,
                    source: PathUtilities.isAppleOwnedPath(appPath) ? .apple : .unknown,
                    timestamps: PathUtilities.timestamps(for: appPath),
                    rawMetadata: [
                        "NSDockTilePlugIn": .string(dockTilePlugin),
                        "ParentApp": .string(appName),
                        "PluginPath": .string(pluginPath),
                    ]
                )
                if !PathUtilities.exists(pluginPath) {
                    item.riskReasons.append(
                        "Declared Dock tile plugin is missing: \(pluginPath)"
                    )
                }
                outcome.items.append(item)
            }
        }

        return outcome
    }
}
