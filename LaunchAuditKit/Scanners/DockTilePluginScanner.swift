import Foundation

public struct DockTilePluginScanner: PersistenceScanner {
    public let category = PersistenceCategory.dockTilePlugins
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        ["/Applications"]
    }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        var items: [PersistenceItem] = []

        // Check apps in /Applications for DockTile plugins
        let appsDir = "/Applications"
        guard PathUtilities.exists(appsDir) else { return items }

        let apps = PathUtilities.listBundles(in: appsDir, withExtension: "app")
        for appPath in apps {
            let infoPlistPath = (appPath as NSString).appendingPathComponent("Contents/Info.plist")
            guard PathUtilities.exists(infoPlistPath),
                  let dict = try? PlistParser().parse(at: infoPlistPath),
                  let dockTilePlugin = dict["NSDockTilePlugIn"] as? String else { continue }

            let appName = ((appPath as NSString).lastPathComponent as NSString).deletingPathExtension
            let pluginPath = (appPath as NSString)
                .appendingPathComponent("Contents/PlugIns/\(dockTilePlugin)")
            let timestamps = PathUtilities.timestamps(for: appPath)

            items.append(PersistenceItem(
                category: category,
                name: "\(appName) Dock Tile Plugin",
                label: dict["CFBundleIdentifier"] as? String,
                configPath: appPath,
                executablePath: pluginPath,
                isEnabled: true,
                runContext: .onDemand,
                owner: .system,
                timestamps: timestamps,
                rawMetadata: [
                    "NSDockTilePlugIn": .string(dockTilePlugin),
                    "ParentApp": .string(appName)
                ]
            ))
        }

        return items
    }
}
