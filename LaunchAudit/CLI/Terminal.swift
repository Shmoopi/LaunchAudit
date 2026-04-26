import Foundation

// MARK: - ANSI Terminal Formatting

/// Terminal output utilities with ANSI color support and structured formatting.
enum Terminal {

    // MARK: - Bundle Info

    static let appVersion: String =
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.0.0"

    static let appCopyright: String =
        Bundle.main.object(forInfoDictionaryKey: "NSHumanReadableCopyright") as? String ?? "Shmoopi LLC"

    /// Whether color output is enabled (respects NO_COLOR, pipe detection).
    nonisolated(unsafe) static var colorEnabled: Bool = {
        if ProcessInfo.processInfo.environment["NO_COLOR"] != nil { return false }
        return isatty(STDOUT_FILENO) != 0
    }()

    /// Whether stderr is a terminal (for progress display).
    static let stderrIsTerminal: Bool = isatty(STDERR_FILENO) != 0

    // MARK: - ANSI Codes

    private static let reset     = "\u{001B}[0m"
    private static let bold      = "\u{001B}[1m"
    private static let dim       = "\u{001B}[2m"
    private static let red       = "\u{001B}[31m"
    private static let green     = "\u{001B}[32m"
    private static let yellow    = "\u{001B}[33m"
    private static let blue      = "\u{001B}[34m"
    private static let cyan      = "\u{001B}[36m"
    private static let gray      = "\u{001B}[90m"
    private static let brightRed = "\u{001B}[91m"

    // MARK: - Styled Output

    static func styled(_ text: String, _ codes: String...) -> String {
        guard colorEnabled else { return text }
        return codes.joined() + text + reset
    }

    /// Visible (printable) width of a string, stripping ANSI escape sequences.
    static func visibleWidth(_ text: String) -> Int {
        let stripped = text.replacingOccurrences(
            of: "\u{001B}\\[[0-9;]*[A-Za-z]",
            with: "",
            options: .regularExpression
        )
        return stripped.count
    }

    /// Pad a string to a fixed visible column width, ignoring ANSI codes.
    static func padded(_ text: String, toWidth width: Int) -> String {
        let visible = visibleWidth(text)
        guard visible < width else { return text }
        return text + String(repeating: " ", count: width - visible)
    }

    static func riskStyled(_ level: RiskLevel) -> String {
        let label = level.displayName.uppercased()
        switch level {
        case .critical:      return styled(label, bold, brightRed)
        case .high:          return styled(label, bold, red)
        case .medium:        return styled(label, yellow)
        case .low:           return styled(label, green)
        case .informational: return styled(label, dim)
        }
    }

    static func riskBadge(_ level: RiskLevel) -> String {
        let label = level.displayName.uppercased()
        let padded = label.padding(toLength: 13, withPad: " ", startingAt: 0)
        switch level {
        case .critical:      return styled(padded, bold, brightRed)
        case .high:          return styled(padded, bold, red)
        case .medium:        return styled(padded, yellow)
        case .low:           return styled(padded, green)
        case .informational: return styled(padded, dim)
        }
    }

    // MARK: - Print Helpers

    static func write(_ text: String) {
        print(text)
    }

    static func writeErr(_ text: String) {
        FileHandle.standardError.write(Data((text + "\n").utf8))
    }

    static func error(_ message: String) {
        let prefix = colorEnabled ? styled("error:", bold, red) : "error:"
        writeErr("\(prefix) \(message)")
    }

    static func warning(_ message: String) {
        let prefix = colorEnabled ? styled("warning:", bold, yellow) : "warning:"
        writeErr("\(prefix) \(message)")
    }

    // MARK: - Progress Display

    /// Overwrite the current stderr line with a progress message.
    static func progress(_ text: String) {
        guard stderrIsTerminal else { return }
        let line = "\r\u{001B}[K\(text)"
        FileHandle.standardError.write(Data(line.utf8))
    }

    /// Clear the progress line and move to a new line.
    static func clearProgress() {
        guard stderrIsTerminal else { return }
        FileHandle.standardError.write(Data("\r\u{001B}[K".utf8))
    }

    // MARK: - Structured Formatting

    static func header(_ title: String) {
        write(styled(title, bold))
        write(String(repeating: "-", count: min(title.count + 4, 60)))
    }

    static func sectionHeader(_ title: String) {
        write("")
        write(styled(title, bold, cyan))
        write(String(repeating: "-", count: 60))
    }

    static func keyValue(_ key: String, _ value: String, indent: Int = 2) {
        let padding = String(repeating: " ", count: indent)
        let keyPadded = (key + ":").padding(toLength: 14, withPad: " ", startingAt: 0)
        write("\(padding)\(styled(keyPadded, dim))\(value)")
    }

    // MARK: - Scan Result Formatting

    static func printScanHeader(_ result: ScanResult) {
        write("")
        write(styled("LaunchAudit v\(appVersion)", bold) + styled(" -- macOS Persistence Auditor", dim))
        write(String(repeating: "=", count: 60))
        write("")
        keyValue("Host", result.hostname)
        keyValue("OS", result.osVersion)
        keyValue("Scanned", result.scanDate.formatted(
            .dateTime.year().month().day().hour().minute().second()
        ))
        keyValue("Duration", String(format: "%.1fs", result.scanDuration))
        write("")
    }

    static func printRiskSummary(_ result: ScanResult, hideApple: Bool) {
        let items = hideApple
            ? result.items.filter { !$0.isAppleSignedAndNotarized }
            : result.items

        let counts: [(RiskLevel, Int)] = RiskLevel.allCases.reversed().map { level in
            (level, items.filter { $0.riskLevel == level }.count)
        }
        let total = items.count
        let thirdParty = items.filter { !$0.source.isApple }.count
        let unsigned = items.filter { $0.signingInfo?.isSigned == false }.count

        sectionHeader("RISK SUMMARY")
        write("")

        for (level, count) in counts {
            let badge = riskBadge(level)
            let countStr = String(count).padding(toLength: 6, withPad: " ", startingAt: 0)
            write("  \(badge) \(styled(countStr, bold))")
        }

        write("  " + String(repeating: "-", count: 20))
        write("  \(styled("Total:", dim))         \(styled(String(total), bold)) items")
        write("  \(styled("Third-party:", dim))    \(thirdParty)")
        write("  \(styled("Unsigned:", dim))       \(unsigned)")
        write("")
    }

    static func printAttentionItems(_ items: [PersistenceItem]) {
        let critical = items.filter { $0.riskLevel == .critical }
        let high = items.filter { $0.riskLevel == .high }
        let attention = critical + high

        guard !attention.isEmpty else { return }

        sectionHeader("ATTENTION REQUIRED (\(attention.count) items)")
        write("")

        for item in attention {
            let badge = riskStyled(item.riskLevel)
            write("  \(styled(">", bold)) \(styled(item.name, bold))  \(badge)")

            keyValue("Category", item.category.displayName, indent: 4)

            if let config = item.configPath {
                keyValue("Config", config, indent: 4)
            }
            if let exec = item.executablePath {
                keyValue("Executable", exec, indent: 4)
            }
            if let signing = item.signingInfo {
                let status = signing.isSigned
                    ? (signing.isNotarized ? "Yes (notarized)" : "Yes (not notarized)")
                    : "No"
                keyValue("Signed", status, indent: 4)
            }
            if !item.riskReasons.isEmpty {
                keyValue("Reasons", item.riskReasons[0], indent: 4)
                for reason in item.riskReasons.dropFirst() {
                    write("                  \(reason)")
                }
            }
            write("")
        }
    }

    static func printCategoryTable(_ items: [PersistenceItem], category: PersistenceCategory) {
        guard !items.isEmpty else { return }

        let sorted = items.sorted { $0.riskLevel > $1.riskLevel }
        let countStr = "\(items.count) item\(items.count == 1 ? "" : "s")"

        write("")
        write(styled("-- \(category.displayName) (\(countStr)) ", bold)
              + String(repeating: "-", count: max(0, 50 - category.displayName.count)))
        write("")

        // Column headers
        let hRisk   = "RISK".padding(toLength: 14, withPad: " ", startingAt: 0)
        let hName   = "NAME".padding(toLength: 32, withPad: " ", startingAt: 0)
        let hSigned = "SIGNED".padding(toLength: 8, withPad: " ", startingAt: 0)
        let hSource = "SOURCE"
        write("  \(styled(hRisk + hName + hSigned + hSource, dim))")

        for item in sorted {
            let risk = padded(riskStyled(item.riskLevel), toWidth: 14)
            let name = String(item.name.prefix(30))
                .padding(toLength: 32, withPad: " ", startingAt: 0)
            let signed: String
            if let info = item.signingInfo {
                signed = info.isSigned ? "Yes" : styled("No", red)
            } else {
                signed = styled("--", dim)
            }
            let signedCol = padded(signed, toWidth: 8)
            let source = item.source.displayName

            write("  \(risk)\(name)\(signedCol)\(source)")
        }
    }

    /// Risk label with ANSI color, returns raw width of the visible text.
    private static func riskLabel(_ level: RiskLevel) -> String {
        riskStyled(level)
    }

    static func printErrors(_ errors: [ScanError]) {
        guard !errors.isEmpty else { return }

        sectionHeader("SCAN ERRORS (\(errors.count))")
        write("")

        for err in errors {
            let prefix = err.isPermissionDenied
                ? styled("[Permission Denied]", yellow)
                : styled("[Error]", red)
            write("  \(prefix) \(err.category.displayName): \(err.message)")
            if let path = err.path {
                write("    \(styled(path, dim))")
            }
        }
        write("")
    }

    // MARK: - Verbose Item Display

    static func printItemVerbose(_ item: PersistenceItem) {
        let badge = riskStyled(item.riskLevel)
        write("  \(styled(">", bold)) \(styled(item.name, bold))  \(badge)")

        keyValue("Category", item.category.displayName, indent: 4)

        if let label = item.label {
            keyValue("Label", label, indent: 4)
        }
        if let config = item.configPath {
            keyValue("Config", config, indent: 4)
        }
        if let exec = item.executablePath {
            keyValue("Executable", exec, indent: 4)
        }
        if !item.arguments.isEmpty {
            keyValue("Arguments", item.arguments.joined(separator: " "), indent: 4)
        }

        keyValue("Status", item.isEnabled ? "Enabled" : styled("Disabled", dim), indent: 4)
        keyValue("Run Context", item.runContext.rawValue, indent: 4)
        keyValue("Owner", item.owner.displayName, indent: 4)

        if let signing = item.signingInfo {
            let signedStr: String
            if signing.isSigned {
                if signing.isAppleSigned {
                    signedStr = styled("Yes (Apple)", green)
                } else if signing.isNotarized {
                    signedStr = styled("Yes (notarized)", green)
                } else if signing.isAdHocSigned {
                    signedStr = styled("Ad-hoc", yellow)
                } else {
                    signedStr = styled("Yes (not notarized)", yellow)
                }
            } else {
                signedStr = styled("No", red)
            }
            keyValue("Signed", signedStr, indent: 4)

            if let team = signing.teamIdentifier {
                keyValue("Team ID", team, indent: 4)
            }
            if let bundle = signing.bundleIdentifier {
                keyValue("Bundle ID", bundle, indent: 4)
            }
        }

        keyValue("Source", item.source.displayName, indent: 4)

        if let created = item.timestamps.created {
            keyValue("Created", created.formatted(.dateTime), indent: 4)
        }
        if let modified = item.timestamps.modified {
            keyValue("Modified", modified.formatted(.dateTime), indent: 4)
        }

        if !item.riskReasons.isEmpty {
            keyValue("Reasons", item.riskReasons[0], indent: 4)
            for reason in item.riskReasons.dropFirst() {
                write("                  \(reason)")
            }
        }
        write("")
    }

    // MARK: - Quiet Output

    static func printQuiet(_ result: ScanResult, hideApple: Bool) {
        let items = hideApple
            ? result.items.filter { !$0.isAppleSignedAndNotarized }
            : result.items

        let critical = items.filter { $0.riskLevel == .critical }.count
        let high = items.filter { $0.riskLevel == .high }.count
        let medium = items.filter { $0.riskLevel == .medium }.count
        let low = items.filter { $0.riskLevel == .low }.count
        let info = items.filter { $0.riskLevel == .informational }.count

        write("critical=\(critical) high=\(high) medium=\(medium) low=\(low) info=\(info) total=\(items.count)")
    }

    // MARK: - Category / Group Listing

    static func printCategoryList(group: CategoryGroup? = nil) {
        if let group = group {
            write("")
            header("Categories in \(group.rawValue)")
            write("")

            for cat in group.categories {
                let id = cat.rawValue.padding(toLength: 28, withPad: " ", startingAt: 0)
                let name = cat.displayName.padding(toLength: 28, withPad: " ", startingAt: 0)
                write("    \(styled(id, dim))  \(name)")
            }
        } else {
            write("")
            header("All Persistence Categories")
            write("")

            for grp in CategoryGroup.allCases {
                write(styled("  \(grp.rawValue)", bold, cyan))
                for cat in grp.categories {
                    let id = cat.rawValue.padding(toLength: 28, withPad: " ", startingAt: 0)
                    let name = cat.displayName.padding(toLength: 28, withPad: " ", startingAt: 0)
                    write("    \(styled(id, dim))  \(name)")
                }
                write("")
            }
        }

        write(styled("  \(PersistenceCategory.allCases.count) categories in \(CategoryGroup.allCases.count) groups", dim))
        write("")
    }

    static func printGroupList() {
        write("")
        header("Category Groups")
        write("")

        for group in CategoryGroup.allCases {
            let cats = group.categories
            write("  \(styled(group.rawValue, bold, cyan))")
            for cat in cats {
                write("    \(styled("*", dim)) \(cat.displayName) \(styled("(\(cat.rawValue))", dim))")
            }
            write("")
        }
    }

    // MARK: - Footer

    static func printFooter(_ result: ScanResult, isRoot: Bool) {
        write("")
        write(String(repeating: "=", count: 60))

        let total = result.items.count
        let critical = result.items.filter { $0.riskLevel == .critical }.count
        let high = result.items.filter { $0.riskLevel == .high }.count
        let unsigned = result.items.filter { $0.signingInfo?.isSigned == false }.count

        var parts: [String] = ["\(total) items"]
        if critical > 0 { parts.append(styled("\(critical) critical", bold, brightRed)) }
        if high > 0 { parts.append(styled("\(high) high", bold, red)) }
        if unsigned > 0 { parts.append(styled("\(unsigned) unsigned", yellow)) }
        write("  \(styled("Scan complete:", bold)) \(parts.joined(separator: ", "))")

        let permErrors = result.errors.filter { $0.isPermissionDenied }.count
        if !isRoot && permErrors > 0 {
            write("")
            write(styled("  ! \(permErrors) location\(permErrors == 1 ? "" : "s") could not be accessed (permission denied)", yellow))
            write(styled("    Run with sudo for a full scan: sudo launchaudit scan", dim))
        } else if !isRoot {
            write("")
            write(styled("  Note: running without root privileges -- some system locations may not be visible.", dim))
            write(styled("  Run with sudo for a complete audit: sudo launchaudit scan", dim))
        }

        write("")
    }

    // MARK: - Version

    static func printVersion() {
        write("launchaudit \(appVersion)")
        write("macOS Persistence Auditor")
        write(appCopyright)
    }

    // MARK: - Usage / Help

    static func printUsage() {
        write(styled("USAGE:", bold))
        write("  launchaudit <command> [options]")
        write("")
        write(styled("COMMANDS:", bold))
        write("  scan              Scan for persistence mechanisms (default)")
        write("  categories        List all persistence categories")
        write("  groups            List all category groups")
        write("  export <file>     Convert a JSON scan result to another format")
        write("  version           Show version information")
        write("  help              Show this help message")
        write("")
        write("  Run \(styled("launchaudit help <command>", bold)) for command-specific options.")
        write("")
    }

    static func printScanHelp() {
        write(styled("USAGE:", bold))
        write("  launchaudit scan [options]")
        write("")
        write(styled("OUTPUT OPTIONS:", bold))
        write("  --format <fmt>        Output format: table, json, csv, html (default: table)")
        write("  -o, --output <path>   Write output to file (format auto-detected from extension)")
        write("  --no-color            Disable colored output")
        write("  --no-progress         Disable progress display")
        write("  --quiet               Machine-readable summary (key=value pairs)")
        write("  --verbose             Show full details for every item")
        write("")
        write(styled("FILTER OPTIONS:", bold))
        write("  --show-apple          Include Apple-signed items (hidden by default)")
        write("  --min-risk <level>    Minimum risk: informational, low, medium, high, critical")
        write("  --unsigned-only       Show only unsigned items")
        write("  --third-party         Show only third-party items")
        write("  --search <query>      Filter items by text search")
        write("  --category <id>       Only scan a specific category (repeatable)")
        write("  --group <name>        Only scan categories in a group (repeatable)")
        write("")
        write(styled("EXAMPLES:", bold))
        write("  launchaudit scan")
        write("  launchaudit scan --min-risk high")
        write("  launchaudit scan --format json -o report.json")
        write("  launchaudit scan --unsigned-only --verbose")
        write("  launchaudit scan --category launchDaemons --category launchAgents")
        write("  launchaudit scan --group \"System Services\"")
        write("  launchaudit scan --third-party --format csv")
        write("")
    }

    static func printExportHelp() {
        write(styled("USAGE:", bold))
        write("  launchaudit export <input.json> [options]")
        write("")
        write(styled("OPTIONS:", bold))
        write("  --format <fmt>        Output format: json, csv, html (default: json)")
        write("  -o, --output <path>   Write to file (format auto-detected from extension)")
        write("")
        write(styled("DESCRIPTION:", bold))
        write("  Convert a previously saved JSON scan result to another format.")
        write("  Use this to generate HTML reports or CSV exports from saved scans.")
        write("")
        write(styled("EXAMPLES:", bold))
        write("  launchaudit export scan.json --format html -o report.html")
        write("  launchaudit export scan.json --format csv")
        write("")
    }

    static func printCategoriesHelp() {
        write(styled("USAGE:", bold))
        write("  launchaudit categories [options]")
        write("")
        write(styled("OPTIONS:", bold))
        write("  --group <name>    Show only categories in the specified group")
        write("")
    }
}
