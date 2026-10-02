import Foundation

public struct PeriodicScanner: PersistenceScanner {
    public let category = PersistenceCategory.periodicTasks
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        [
            "/etc/periodic/daily",
            "/etc/periodic/weekly",
            "/etc/periodic/monthly",
            "/usr/local/etc/periodic/daily",
            "/usr/local/etc/periodic/weekly",
            "/usr/local/etc/periodic/monthly"
        ]
    }

    public init() {}

    public func scan() async throws -> ScanOutcome {
        var outcome = ScanOutcome()

        // Derived from `scanPaths` so the declared list and the scanned list
        // cannot drift apart.
        for directory in scanPaths {
            let period = (directory as NSString).lastPathComponent
            let (scripts, errors) = entries(in: directory)
            outcome.errors += errors

            for script in scripts {
                let name = (script as NSString).lastPathComponent
                let timestamps = PathUtilities.timestamps(for: script)

                outcome.items.append(PersistenceItem(
                    category: category,
                    name: name,
                    configPath: script,
                    executablePath: script,
                    isEnabled: true,
                    runContext: .scheduled,
                    owner: .system,
                    timestamps: timestamps,
                    rawMetadata: [
                        "Period": .string(period),
                        "Directory": .string(directory)
                    ]
                ))
            }
        }

        return outcome
    }
}
