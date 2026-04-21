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

    public func scan() async throws -> [PersistenceItem] {
        var items: [PersistenceItem] = []

        let periods: [(String, String)] = [
            ("daily", "/etc/periodic/daily"),
            ("weekly", "/etc/periodic/weekly"),
            ("monthly", "/etc/periodic/monthly"),
            ("daily", "/usr/local/etc/periodic/daily"),
            ("weekly", "/usr/local/etc/periodic/weekly"),
            ("monthly", "/usr/local/etc/periodic/monthly"),
        ]

        for (period, directory) in periods {
            guard PathUtilities.exists(directory) else { continue }
            let scripts = PathUtilities.listFiles(in: directory)

            for script in scripts {
                let name = (script as NSString).lastPathComponent
                guard !name.hasPrefix(".") else { continue }
                let timestamps = PathUtilities.timestamps(for: script)

                items.append(PersistenceItem(
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

        return items
    }
}
