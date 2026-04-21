import Foundation

public struct StartupItemScanner: PersistenceScanner {
    public let category = PersistenceCategory.startupItems
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        [
            "/Library/StartupItems",
            "/System/Library/StartupItems"
        ]
    }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        var items: [PersistenceItem] = []

        for directory in scanPaths {
            guard PathUtilities.exists(directory) else { continue }
            let subdirs = PathUtilities.listDirectories(in: directory)

            for subdir in subdirs {
                let name = (subdir as NSString).lastPathComponent
                let startupScript = (subdir as NSString).appendingPathComponent(name)
                let startupPlist = (subdir as NSString).appendingPathComponent("StartupParameters.plist")
                let timestamps = PathUtilities.timestamps(for: subdir)

                var metadata: [String: PlistValue] = [
                    "Type": .string("StartupItem"),
                    "Directory": .string(directory)
                ]

                if PathUtilities.exists(startupPlist),
                   let dict = try? PlistParser().parse(at: startupPlist) {
                    metadata = PlistParser().toMetadata(dict)
                }

                items.append(PersistenceItem(
                    category: category,
                    name: name,
                    configPath: startupPlist,
                    executablePath: PathUtilities.exists(startupScript) ? startupScript : nil,
                    isEnabled: true,
                    runContext: .boot,
                    owner: .system,
                    riskLevel: .high,
                    riskReasons: ["Uses deprecated StartupItems mechanism"],
                    timestamps: timestamps,
                    rawMetadata: metadata
                ))
            }
        }

        return items
    }
}
