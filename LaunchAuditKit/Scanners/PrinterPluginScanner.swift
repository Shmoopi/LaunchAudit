import Foundation

public struct PrinterPluginScanner: PersistenceScanner {
    public let category = PersistenceCategory.printerPlugins
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        ["/Library/Printers"]
    }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        var items: [PersistenceItem] = []
        let directory = "/Library/Printers"

        guard PathUtilities.exists(directory) else { return items }

        // Scan for printer driver bundles
        let subdirs = PathUtilities.listDirectories(in: directory)
        for subdir in subdirs {
            let name = (subdir as NSString).lastPathComponent
            let timestamps = PathUtilities.timestamps(for: subdir)

            // Look for executable bundles within
            let infoPlistPath = (subdir as NSString).appendingPathComponent("Contents/Info.plist")
            var label: String?
            if PathUtilities.exists(infoPlistPath),
               let dict = try? PlistParser().parse(at: infoPlistPath) {
                label = dict["CFBundleIdentifier"] as? String
            }

            items.append(PersistenceItem(
                category: category,
                name: name,
                label: label,
                configPath: subdir,
                isEnabled: true,
                runContext: .onDemand,
                owner: .system,
                timestamps: timestamps,
                rawMetadata: ["Directory": .string(directory)]
            ))
        }

        return items
    }
}
