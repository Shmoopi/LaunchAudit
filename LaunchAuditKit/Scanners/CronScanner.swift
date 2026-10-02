import Foundation

public struct CronScanner: PersistenceScanner {
    public let category = PersistenceCategory.cronJobs
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        [
            "/etc/crontab",
            "/etc/cron.d",
            "/private/var/at/tabs",
            "/private/var/at/jobs",
        ]
    }

    public init() {}

    public func scan() async throws -> ScanOutcome {
        var outcome = ScanOutcome()

        // Current user's crontab
        if let output = await ProcessRunner.shared.tryRun("/usr/bin/crontab", arguments: ["-l"]) {
            outcome.items += parseCrontab(output, owner: .user(PathUtilities.currentUser))
        }

        // System crontab. Six-field format: the field after the schedule is the
        // user the job runs as, not the command.
        if PathUtilities.exists("/etc/crontab") {
            do {
                let text = try SafeRead.text(atPath: "/etc/crontab")
                outcome.items += parseCrontab(
                    text, owner: .system, configPath: "/etc/crontab", hasUserField: true
                )
            } catch {
                outcome.errors.append(scanError(error, path: "/etc/crontab"))
            }
        }

        // Drop-in crontabs, also in six-field format.
        let (dropIns, dropInErrors) = entries(in: "/etc/cron.d")
        outcome.errors += dropInErrors
        for file in dropIns {
            do {
                let text = try SafeRead.text(atPath: file)
                outcome.items += parseCrontab(
                    text, owner: .system, configPath: file, hasUserField: true
                )
            } catch {
                outcome.errors.append(scanError(error, path: file))
            }
        }

        // Per-user crontab spool files.
        let (tabs, tabErrors) = entries(in: "/private/var/at/tabs")
        outcome.errors += tabErrors
        for file in tabs {
            let username = (file as NSString).lastPathComponent
            do {
                let text = try SafeRead.text(atPath: file)
                outcome.items += parseCrontab(text, owner: .user(username), configPath: file)
            } catch {
                outcome.errors.append(scanError(error, path: file))
            }
        }

        // `at` jobs.
        let (jobs, jobErrors) = entries(in: "/private/var/at/jobs")
        outcome.errors += jobErrors
        // `at` only executes when com.apple.atrun is enabled, and it ships
        // disabled. Saying so keeps these from reading as live scheduled tasks.
        let atrunEnabled = await Self.isAtrunEnabled()
        for job in jobs {
            let name = (job as NSString).lastPathComponent
            var item = PersistenceItem(
                category: category,
                name: "at job: \(name)",
                configPath: job,
                isEnabled: atrunEnabled,
                runContext: .scheduled,
                owner: .system,
                timestamps: PathUtilities.timestamps(for: job),
                rawMetadata: [
                    "Type": .string("at"),
                    "AtrunEnabled": .bool(atrunEnabled),
                ]
            )
            if !atrunEnabled {
                item.riskMitigations.append(
                    "com.apple.atrun is disabled, so queued at jobs will not run"
                )
            }
            outcome.items.append(item)
        }

        return outcome
    }

    /// `at` jobs are dispatched by com.apple.atrun, which Apple ships disabled.
    private static func isAtrunEnabled() async -> Bool {
        let plist = "/System/Library/LaunchDaemons/com.apple.atrun.plist"
        guard let dict = try? PlistParser().parse(at: plist) else { return false }
        let disabledInPlist = (dict["Disabled"] as? Bool) ?? false
        let label = dict["Label"] as? String ?? "com.apple.atrun"
        return LaunchdStateResolver.shared.isEnabled(
            label: label, plistDisabledKey: disabledInPlist, owner: .system
        ).isEnabled
    }

    /// Parse crontab content.
    ///
    /// - Parameter hasUserField: true for `/etc/crontab` and `/etc/cron.d`, whose
    ///   format inserts a user column between the schedule and the command. Without
    ///   this the user name was parsed as the executable, so every system cron
    ///   entry reported `root` as its binary with all arguments shifted by one.
    func parseCrontab(
        _ content: String,
        owner: ItemOwner,
        configPath: String? = nil,
        hasUserField: Bool = false
    ) -> [PersistenceItem] {
        var items: [PersistenceItem] = []

        for line in content.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            // Skip comments and empty lines
            guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { continue }
            // Skip variable assignments (PATH=, SHELL=, MAILTO=)
            guard !trimmed.contains("=") || trimmed.first?.isNumber == true
                || trimmed.first == "*" || trimmed.first == "@" else { continue }

            let parts = trimmed.components(separatedBy: .whitespaces).filter { !$0.isEmpty }

            let isSpecial = trimmed.hasPrefix("@")
            // A special schedule needs only two tokens: `@reboot /path/to/thing`.
            // Requiring six unconditionally discarded every `@reboot` entry —
            // the primary cron persistence vector — before the `@` branch ran.
            let scheduleFieldCount = isSpecial ? 1 : 5
            let minimumFields = scheduleFieldCount + (hasUserField ? 1 : 0) + 1
            guard parts.count >= minimumFields else { continue }

            let schedule = parts.prefix(scheduleFieldCount).joined(separator: " ")
            var remainder = Array(parts.dropFirst(scheduleFieldCount))

            var runAsUser: String?
            if hasUserField, !remainder.isEmpty {
                runAsUser = remainder.removeFirst()
            }

            let command = remainder.joined(separator: " ")
            guard !command.isEmpty else { continue }

            let executable = remainder.first ?? command
            let effectiveOwner: ItemOwner = {
                guard let runAsUser else { return owner }
                return runAsUser == "root" ? .system : .user(runAsUser)
            }()

            var metadata: [String: PlistValue] = [
                "Schedule": .string(schedule),
                "Command": .string(command),
                "Type": .string("cron"),
            ]
            if let runAsUser { metadata["RunAsUser"] = .string(runAsUser) }

            items.append(PersistenceItem(
                category: category,
                name: String(command.prefix(80)),
                configPath: configPath,
                executablePath: executable,
                arguments: remainder,
                isEnabled: true,
                runContext: schedule.hasPrefix("@reboot") ? .boot : .scheduled,
                owner: effectiveOwner,
                rawMetadata: metadata
            ))
        }

        return items
    }
}
