import Foundation

public struct CronScanner: PersistenceScanner {
    public let category = PersistenceCategory.cronJobs
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        [
            "/etc/crontab",
            "/private/var/at/tabs",
            "/private/var/at/jobs"
        ]
    }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        var items: [PersistenceItem] = []

        // Current user's crontab
        if let output = await ProcessRunner.shared.tryRun("/usr/bin/crontab", arguments: ["-l"]) {
            let entries = parseCrontab(output, owner: .user(PathUtilities.currentUser))
            items.append(contentsOf: entries)
        }

        // System crontab
        if PathUtilities.exists("/etc/crontab") {
            if let data = try? String(contentsOfFile: "/etc/crontab", encoding: .utf8) {
                let entries = parseCrontab(data, owner: .system)
                items.append(contentsOf: entries)
            }
        }

        // User crontab files in /private/var/at/tabs/
        let tabsDir = "/private/var/at/tabs"
        if PathUtilities.exists(tabsDir) {
            let files = PathUtilities.listFiles(in: tabsDir)
            for file in files {
                let username = (file as NSString).lastPathComponent
                if let data = try? String(contentsOfFile: file, encoding: .utf8) {
                    let entries = parseCrontab(data, owner: .user(username), configPath: file)
                    items.append(contentsOf: entries)
                }
            }
        }

        // at jobs
        let atDir = "/private/var/at/jobs"
        if PathUtilities.exists(atDir) {
            let jobs = PathUtilities.listFiles(in: atDir)
            for job in jobs {
                let name = (job as NSString).lastPathComponent
                let timestamps = PathUtilities.timestamps(for: job)
                items.append(PersistenceItem(
                    category: category,
                    name: "at job: \(name)",
                    configPath: job,
                    isEnabled: true,
                    runContext: .scheduled,
                    owner: .system,
                    timestamps: timestamps,
                    rawMetadata: ["Type": .string("at")]
                ))
            }
        }

        return items
    }

    private func parseCrontab(_ content: String, owner: ItemOwner, configPath: String? = nil) -> [PersistenceItem] {
        var items: [PersistenceItem] = []

        for line in content.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            // Skip comments and empty lines
            guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { continue }
            // Skip variable assignments
            guard !trimmed.contains("=") || trimmed.first?.isNumber == true || trimmed.first == "*" || trimmed.first == "@" else { continue }

            // Parse the cron line
            let parts = trimmed.components(separatedBy: .whitespaces).filter { !$0.isEmpty }
            guard parts.count >= 6 else { continue }

            let schedule: String
            let command: String

            if trimmed.hasPrefix("@") {
                // Special schedule (@reboot, @daily, etc.)
                schedule = parts[0]
                command = parts.dropFirst(1).joined(separator: " ")
            } else {
                schedule = parts.prefix(5).joined(separator: " ")
                command = parts.dropFirst(5).joined(separator: " ")
            }

            let executable = command.components(separatedBy: .whitespaces).first ?? command

            items.append(PersistenceItem(
                category: category,
                name: command.prefix(80).description,
                configPath: configPath,
                executablePath: executable,
                arguments: Array(command.components(separatedBy: .whitespaces).dropFirst()),
                isEnabled: true,
                runContext: schedule.contains("@reboot") ? .boot : .scheduled,
                owner: owner,
                rawMetadata: [
                    "Schedule": .string(schedule),
                    "Command": .string(command),
                    "Type": .string("cron")
                ]
            ))
        }

        return items
    }
}
