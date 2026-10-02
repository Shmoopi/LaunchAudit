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

    public func scan() async throws -> ScanOutcome {
        var outcome = ScanOutcome()

        for directory in scanPaths {
            let (subdirs, errors) = entries(in: directory, includeDirectories: true)
            outcome.errors += errors

            for subdir in subdirs where PathUtilities.isDirectory(subdir) {
                let name = (subdir as NSString).lastPathComponent
                let startupScript = (subdir as NSString).appendingPathComponent(name)
                let startupPlist = (subdir as NSString)
                    .appendingPathComponent("StartupParameters.plist")
                let hasPlist = PathUtilities.exists(startupPlist)

                var metadata: [String: PlistValue] = [
                    "Type": .string("StartupItem"),
                    "Directory": .string(directory),
                ]

                // Merge rather than replace: assigning the parsed plist over the
                // base dictionary discarded the Type and Directory keys set above.
                if hasPlist, let dict = try? PlistParser().parse(at: startupPlist) {
                    metadata.merge(PlistParser().toMetadata(dict)) { _, new in new }
                }

                outcome.items.append(PersistenceItem(
                    category: category,
                    name: name,
                    // Only claim a config path when the file is actually there;
                    // otherwise the location dimension reasons about a path that
                    // does not exist.
                    configPath: hasPlist ? startupPlist : subdir,
                    executablePath: PathUtilities.exists(startupScript) ? startupScript : nil,
                    isEnabled: true,
                    runContext: .boot,
                    owner: .system,
                    riskLevel: .high,
                    riskReasons: [
                        "StartupItems were removed from macOS long ago and are no "
                            + "longer executed by the system, so this entry was left "
                            + "behind or planted",
                    ],
                    timestamps: PathUtilities.timestamps(for: subdir),
                    rawMetadata: metadata
                ))
            }
        }

        return outcome
    }
}
