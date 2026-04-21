import Foundation

public struct DylibInjectionScanner: PersistenceScanner {
    public let category = PersistenceCategory.dylibInjection
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        [
            "/etc/launchd.conf",
            PathUtilities.expandTilde("~/.MacOSX/environment.plist")
        ]
    }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        var items: [PersistenceItem] = []

        // Check /etc/launchd.conf (deprecated but still worth checking)
        let launchdConf = "/etc/launchd.conf"
        if PathUtilities.exists(launchdConf) {
            if let content = try? String(contentsOfFile: launchdConf, encoding: .utf8) {
                let timestamps = PathUtilities.timestamps(for: launchdConf)
                for line in content.components(separatedBy: "\n") {
                    let trimmed = line.trimmingCharacters(in: .whitespaces)
                    guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { continue }
                    if trimmed.contains("DYLD_INSERT_LIBRARIES") {
                        items.append(PersistenceItem(
                            category: category,
                            name: "DYLD_INSERT_LIBRARIES in launchd.conf",
                            configPath: launchdConf,
                            isEnabled: true,
                            runContext: .boot,
                            owner: .system,
                            riskLevel: .critical,
                            riskReasons: ["DYLD_INSERT_LIBRARIES used for dynamic library injection"],
                            timestamps: timestamps,
                            rawMetadata: ["Line": .string(trimmed)]
                        ))
                    }
                }
                // Even if no DYLD, the file existing is noteworthy (deprecated)
                if items.isEmpty {
                    items.append(PersistenceItem(
                        category: category,
                        name: "launchd.conf exists (deprecated)",
                        configPath: launchdConf,
                        isEnabled: true,
                        runContext: .boot,
                        owner: .system,
                        riskLevel: .medium,
                        riskReasons: ["/etc/launchd.conf is deprecated but still present"],
                        timestamps: timestamps,
                        rawMetadata: ["Content": .string(content.prefix(500).description)]
                    ))
                }
            }
        }

        // Check ~/.MacOSX/environment.plist (deprecated)
        let envPlist = PathUtilities.expandTilde("~/.MacOSX/environment.plist")
        if PathUtilities.exists(envPlist) {
            let timestamps = PathUtilities.timestamps(for: envPlist)
            var metadata: [String: PlistValue] = ["Source": .string("environment.plist")]
            var riskReasons = ["Deprecated ~/.MacOSX/environment.plist exists"]

            if let dict = try? PlistParser().parse(at: envPlist) {
                metadata = PlistParser().toMetadata(dict)
                if dict["DYLD_INSERT_LIBRARIES"] != nil {
                    riskReasons.append("Contains DYLD_INSERT_LIBRARIES")
                }
            }

            items.append(PersistenceItem(
                category: category,
                name: "environment.plist",
                configPath: envPlist,
                isEnabled: true,
                runContext: .login,
                owner: .user(PathUtilities.currentUser),
                riskLevel: dict_has_dyld(envPlist) ? .critical : .medium,
                riskReasons: riskReasons,
                timestamps: timestamps,
                rawMetadata: metadata
            ))
        }

        // Scan all launchd plists for DYLD_INSERT_LIBRARIES in EnvironmentVariables
        let launchdDirs = [
            "/Library/LaunchDaemons",
            "/Library/LaunchAgents",
            PathUtilities.expandTilde("~/Library/LaunchAgents")
        ]

        for dir in launchdDirs {
            let plists = PathUtilities.listFiles(in: dir, withExtension: "plist")
            for plistPath in plists {
                guard let dict = try? PlistParser().parse(at: plistPath),
                      let envVars = dict["EnvironmentVariables"] as? [String: Any],
                      envVars["DYLD_INSERT_LIBRARIES"] != nil else { continue }

                let dyldValue = envVars["DYLD_INSERT_LIBRARIES"] as? String ?? "unknown"
                let label = dict["Label"] as? String ?? (plistPath as NSString).lastPathComponent
                let timestamps = PathUtilities.timestamps(for: plistPath)

                items.append(PersistenceItem(
                    category: category,
                    name: "DYLD injection in: \(label)",
                    label: label,
                    configPath: plistPath,
                    executablePath: dyldValue,
                    isEnabled: true,
                    runContext: .boot,
                    owner: .system,
                    riskLevel: .critical,
                    riskReasons: [
                        "DYLD_INSERT_LIBRARIES found in launchd plist",
                        "Injected library: \(dyldValue)"
                    ],
                    timestamps: timestamps,
                    rawMetadata: ["DYLD_INSERT_LIBRARIES": .string(dyldValue)]
                ))
            }
        }

        return items
    }

    private func dict_has_dyld(_ path: String) -> Bool {
        guard let dict = try? PlistParser().parse(at: path) else { return false }
        return dict["DYLD_INSERT_LIBRARIES"] != nil
    }
}
