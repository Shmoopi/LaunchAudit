import Foundation

public struct LoginItemScanner: PersistenceScanner {
    public let category = PersistenceCategory.loginItems
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        [
            PathUtilities.expandTilde("~/Library/Application Support/com.apple.backgroundtaskmanagementagent"),
        ]
    }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        var items: [PersistenceItem] = []
        var seenNames = Set<String>()

        // Method 1: Query System Events via osascript for login items.
        // Skip in headless/CLI mode — osascript can trigger GUI permission dialogs.
        // Direct invocation (no /bin/sh fork) plus a 3s cap so a hung
        // System Events doesn't stall the whole scan; BTMScanner is the
        // canonical source on macOS 13+ and runs independently.
        if ProcessInfo.processInfo.environment["LAUNCHAUDIT_HEADLESS"] == nil {
            if let output = await ProcessRunner.shared.tryRun(
                "/usr/bin/osascript",
                arguments: [
                    "-e",
                    "tell application \"System Events\" to get {name, path} of every login item"
                ],
                timeout: 3
            ) {
                let parsed = parseSystemEventsOutput(output)
                for item in parsed {
                    seenNames.insert(item.name.lowercased())
                    items.append(item)
                }
            }
        }

        // Method 2: Check loginwindow plist for AutoLaunchedApplicationDictionary
        let byHostDir = PathUtilities.expandTilde("~/Library/Preferences/ByHost")
        let plistFiles = PathUtilities.listFiles(in: byHostDir, withExtension: "plist")
        for plistPath in plistFiles {
            guard (plistPath as NSString).lastPathComponent.hasPrefix("com.apple.loginwindow") else {
                continue
            }
            if let dict = try? PlistParser().parse(at: plistPath),
               let autoLaunch = dict["AutoLaunchedApplicationDictionary"] as? [[String: Any]] {
                for entry in autoLaunch {
                    let name = entry["Name"] as? String ?? "Unknown"
                    guard !seenNames.contains(name.lowercased()) else { continue }
                    seenNames.insert(name.lowercased())

                    let path = entry["Path"] as? String
                    let hide = entry["Hide"] as? Bool ?? false
                    items.append(PersistenceItem(
                        category: category,
                        name: name,
                        configPath: plistPath,
                        executablePath: path,
                        isEnabled: true,
                        runContext: .login,
                        owner: .user(PathUtilities.currentUser),
                        rawMetadata: [
                            "Hide": .bool(hide),
                            "Source": .string("loginwindow plist")
                        ]
                    ))
                }
            }
        }

        // Method 3: Scan ~/Library/LaunchAgents for login items not covered above
        let userAgentsDir = PathUtilities.expandTilde("~/Library/LaunchAgents")
        if PathUtilities.exists(userAgentsDir) {
            let agentFiles = PathUtilities.listFiles(in: userAgentsDir, withExtension: "plist")
            for agentPath in agentFiles {
                let filename = (agentPath as NSString).lastPathComponent
                let label = (filename as NSString).deletingPathExtension
                guard !seenNames.contains(label.lowercased()) else { continue }

                guard let content = try? Data(contentsOf: URL(fileURLWithPath: agentPath)),
                      let dict = try? PropertyListSerialization.propertyList(
                        from: content, format: nil
                      ) as? [String: Any] else { continue }

                let plistLabel = dict["Label"] as? String ?? label
                guard !seenNames.contains(plistLabel.lowercased()) else { continue }
                seenNames.insert(plistLabel.lowercased())

                let program = dict["Program"] as? String
                let programArgs = dict["ProgramArguments"] as? [String]
                let executable = program ?? programArgs?.first
                let runAtLoad = dict["RunAtLoad"] as? Bool ?? false

                let resolvedExec: String?
                if let exec = executable,
                   exec.hasSuffix(".app") || exec.hasSuffix(".app/") {
                    resolvedExec = resolveAppExecutable(exec) ?? exec
                } else {
                    resolvedExec = executable
                }

                items.append(PersistenceItem(
                    category: category,
                    name: plistLabel,
                    label: plistLabel,
                    configPath: agentPath,
                    executablePath: resolvedExec,
                    isEnabled: !(dict["Disabled"] as? Bool ?? false),
                    runContext: runAtLoad ? .login : .onDemand,
                    owner: .user(PathUtilities.currentUser),
                    rawMetadata: [
                        "Source": .string("~/Library/LaunchAgents")
                    ]
                ))
            }
        }

        return items
    }

    // MARK: - System Events Parsing

    private func parseSystemEventsOutput(_ output: String) -> [PersistenceItem] {
        let trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed != "missing value" else { return [] }

        let names: [String]
        let paths: [String]

        if trimmed.hasPrefix("{") {
            let parts = trimmed.components(separatedBy: "}, {")
            guard parts.count == 2 else {
                let cleaned = trimmed
                    .trimmingCharacters(in: CharacterSet(charactersIn: "{}"))
                return splitPair(cleaned).map { [$0] } ?? []
            }
            let namesPart = parts[0]
                .trimmingCharacters(in: CharacterSet(charactersIn: "{ }"))
            let pathsPart = parts[1]
                .trimmingCharacters(in: CharacterSet(charactersIn: "} "))

            names = namesPart.components(separatedBy: ", ")
                .map { $0.trimmingCharacters(in: .whitespaces) }
            paths = pathsPart.components(separatedBy: ", ")
                .map { $0.trimmingCharacters(in: .whitespaces) }
        } else {
            if let item = splitPair(trimmed) {
                return [item]
            }
            return []
        }

        var items: [PersistenceItem] = []
        for i in 0..<names.count {
            let name = names[i]
            let path = i < paths.count ? paths[i] : nil
            guard !name.isEmpty else { continue }

            let executablePath: String?
            if let p = path {
                if p.hasSuffix(".app") || p.hasSuffix(".app/") {
                    executablePath = resolveAppExecutable(p) ?? p
                } else {
                    executablePath = p
                }
            } else {
                executablePath = nil
            }

            items.append(PersistenceItem(
                category: category,
                name: name,
                configPath: path,
                executablePath: executablePath,
                isEnabled: true,
                runContext: .login,
                owner: .user(PathUtilities.currentUser),
                rawMetadata: ["Source": .string("System Events")]
            ))
        }

        return items
    }

    private func splitPair(_ text: String) -> PersistenceItem? {
        let parts = text.components(separatedBy: ", ")
        guard !parts.isEmpty else { return nil }

        var nameParts: [String] = []
        var path: String?

        for part in parts {
            let cleaned = part.trimmingCharacters(in: .whitespaces)
            if path == nil && (cleaned.hasPrefix("/") || cleaned.hasPrefix("~")) {
                path = cleaned
            } else if path == nil {
                nameParts.append(cleaned)
            }
        }

        let name = nameParts.joined(separator: ", ")
        guard !name.isEmpty else { return nil }

        let executablePath: String?
        if let p = path {
            if p.hasSuffix(".app") || p.hasSuffix(".app/") {
                executablePath = resolveAppExecutable(p) ?? p
            } else {
                executablePath = p
            }
        } else {
            executablePath = nil
        }

        return PersistenceItem(
            category: category,
            name: name,
            configPath: path,
            executablePath: executablePath,
            isEnabled: true,
            runContext: .login,
            owner: .user(PathUtilities.currentUser),
            rawMetadata: ["Source": .string("System Events")]
        )
    }

    private func resolveAppExecutable(_ appPath: String) -> String? {
        let infoPlistPath = (appPath as NSString).appendingPathComponent("Contents/Info.plist")
        guard let dict = try? PlistParser().parse(at: infoPlistPath),
              let execName = dict["CFBundleExecutable"] as? String else {
            return nil
        }
        let execPath = (appPath as NSString)
            .appendingPathComponent("Contents/MacOS/\(execName)")
        return PathUtilities.exists(execPath) ? execPath : nil
    }
}
