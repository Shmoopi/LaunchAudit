import Foundation

public struct LoginItemScanner: PersistenceScanner {
    public let category = PersistenceCategory.loginItems
    public let requiresPrivilege = false

    /// AppleScript that emits one record per line as `name<TAB>path`.
    ///
    /// The previous script returned `{name, path} of every login item`, i.e. two
    /// parallel lists, and the parser assumed osascript would brace them. It does
    /// not — `osascript -e 'return {{"a","b"},{"c","d"}}'` prints `a, b, c, d` —
    /// so five login items were folded into a single item named
    /// "Item1, Item2, Item3, Item4, Item5" carrying only the first path. A
    /// line-delimited record format removes the ambiguity entirely and also
    /// survives application names that contain a comma.
    private static let loginItemsScript = """
    set AppleScript's text item delimiters to linefeed
    set output to {}
    tell application "System Events"
        repeat with anItem in login items
            try
                set itemPath to path of anItem
            on error
                set itemPath to ""
            end try
            set end of output to (name of anItem) & tab & itemPath
        end repeat
    end tell
    return output as text
    """

    public var scanPaths: [String] {
        var paths: [String] = []
        for (_, home) in PathUtilities.scannableHomeDirectories() {
            paths.append((home as NSString).appendingPathComponent("Library/Preferences/ByHost"))
        }
        return paths
    }

    public init() {}

    public func scan() async throws -> ScanOutcome {
        var outcome = ScanOutcome()
        var seenKeys = Set<String>()

        // Method 1: System Events. Skipped when interactive prompts must be
        // avoided — Apple Events raise an Automation consent dialog on first use,
        // and BTMScanner is the canonical source on macOS 13+ anyway.
        if !ScanEnvironment.shared.avoidInteractivePrompts {
            if let output = await ProcessRunner.shared.tryRun(
                "/usr/bin/osascript",
                arguments: ["-e", Self.loginItemsScript],
                timeout: 5
            ) {
                for item in parseSystemEventsOutput(output) {
                    seenKeys.insert(item.name.lowercased())
                    outcome.items.append(item)
                }
            } else {
                outcome.errors.append(ScanError(
                    category: category,
                    message: "Could not query System Events for login items. If macOS "
                        + "denied the Automation prompt, grant access in System Settings → "
                        + "Privacy & Security → Automation.",
                    isPermissionDenied: true
                ))
            }
        }

        // Method 2: loginwindow's AutoLaunchedApplicationDictionary, per user.
        for (user, home) in PathUtilities.scannableHomeDirectories() {
            let byHostDir = (home as NSString).appendingPathComponent("Library/Preferences/ByHost")
            let (plistFiles, listErrors) = entries(in: byHostDir, withExtension: "plist")
            outcome.errors += listErrors

            for plistPath in plistFiles {
                guard (plistPath as NSString).lastPathComponent
                    .hasPrefix("com.apple.loginwindow") else { continue }

                let dict: [String: Any]
                do {
                    dict = try PlistParser().parse(at: plistPath)
                } catch {
                    outcome.errors.append(scanError(error, path: plistPath))
                    continue
                }

                guard let autoLaunch = dict["AutoLaunchedApplicationDictionary"]
                    as? [[String: Any]] else { continue }

                for entry in autoLaunch {
                    let name = entry["Name"] as? String ?? "Unknown"
                    guard !seenKeys.contains(name.lowercased()) else { continue }
                    seenKeys.insert(name.lowercased())

                    let path = entry["Path"] as? String
                    let hide = entry["Hide"] as? Bool ?? false
                    outcome.items.append(PersistenceItem(
                        category: category,
                        name: name,
                        configPath: plistPath,
                        executablePath: path.flatMap { resolveExecutable($0) } ?? path,
                        isEnabled: true,
                        runContext: .login,
                        owner: .user(user),
                        timestamps: PathUtilities.timestamps(for: plistPath),
                        rawMetadata: [
                            "Hide": .bool(hide),
                            "Source": .string("loginwindow plist"),
                        ]
                    ))
                }
            }
        }

        // NOTE: `~/Library/LaunchAgents` is deliberately *not* scanned here.
        // LaunchAgentScanner already covers it, and doing it in both places
        // reported every user agent twice under two different categories, with
        // two different mechanism severities and two different risk scores.

        return outcome
    }

    // MARK: - System Events Parsing

    /// Parse the line-delimited `name<TAB>path` output.
    func parseSystemEventsOutput(_ output: String) -> [PersistenceItem] {
        let trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed != "missing value" else { return [] }

        var items: [PersistenceItem] = []
        for line in trimmed.components(separatedBy: .newlines) {
            guard !line.trimmingCharacters(in: .whitespaces).isEmpty else { continue }

            let fields = line.components(separatedBy: "\t")
            let name = fields[0].trimmingCharacters(in: .whitespaces)
            guard !name.isEmpty, name != "missing value" else { continue }

            var path: String? = fields.count > 1
                ? fields[1].trimmingCharacters(in: .whitespaces)
                : nil
            if path?.isEmpty == true || path == "missing value" { path = nil }

            items.append(PersistenceItem(
                category: category,
                name: name,
                configPath: path,
                executablePath: path.flatMap { resolveExecutable($0) } ?? path,
                isEnabled: true,
                runContext: .login,
                owner: .user(PathUtilities.currentUser),
                timestamps: path.map { PathUtilities.timestamps(for: $0) } ?? ItemTimestamps(),
                rawMetadata: ["Source": .string("System Events")]
            ))
        }

        return items
    }

    /// Resolve an app bundle to the binary inside it so the signature can be
    /// verified; pass other paths through unchanged.
    private func resolveExecutable(_ path: String) -> String? {
        guard path.hasSuffix(".app") || path.hasSuffix(".app/") else { return path }
        let appPath = path.hasSuffix("/") ? String(path.dropLast()) : path
        let infoPlistPath = (appPath as NSString).appendingPathComponent("Contents/Info.plist")
        guard let dict = try? PlistParser().parse(at: infoPlistPath),
              let execName = dict["CFBundleExecutable"] as? String else {
            return appPath
        }
        let execPath = (appPath as NSString)
            .appendingPathComponent("Contents/MacOS/\(execName)")
        return PathUtilities.exists(execPath) ? execPath : appPath
    }
}
