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
        let env = ProcessInfo.processInfo.environment
        // A dumb terminal cannot render escapes even when it is a tty.
        if env["TERM"] == "dumb" { return false }
        if env["NO_COLOR"] != nil { return false }
        // Let a pipe opt back in: `launchaudit scan | less -R` and CI log viewers.
        if env["CLICOLOR_FORCE"] != nil || env["FORCE_COLOR"] != nil { return true }
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

    /// Standard rule width. Every separator derives from this so the output does
    /// not have a ragged right edge.
    static let ruleWidth = 60

    /// Strip control characters from untrusted text before it reaches a terminal.
    ///
    /// Item names, labels, paths, arguments and risk reasons all originate in
    /// attacker-writable files (a launchd `Label`, a filename). Written raw, a
    /// crafted name containing `ESC [ 2K ESC [ 1A` erases its own row and the row
    /// above it, so a malicious entry can hide itself from `launchaudit scan`
    /// output — and with a cursor-positioning prefix it can forge a neighbouring
    /// row's "Signed: Yes (Apple)".
    ///
    /// `visibleWidth` only strips CSI for column math; it never removed the bytes.
    static func sanitize(_ text: String) -> String {
        var out = String.UnicodeScalarView()
        out.reserveCapacity(text.unicodeScalars.count)
        for scalar in text.unicodeScalars {
            switch scalar.value {
            // C0 controls, except tab and newline which callers handle themselves.
            case 0x00...0x08, 0x0B, 0x0C, 0x0E...0x1F:
                out.append("\u{FFFD}")
            case 0x7F:                      // DEL
                out.append("\u{FFFD}")
            case 0x80...0x9F:               // C1, includes 8-bit CSI and OSC
                out.append("\u{FFFD}")
            // Bidi overrides: a cheap way to make `evil.plist` render reversed.
            case 0x202A...0x202E, 0x2066...0x2069:
                out.append("\u{FFFD}")
            default:
                out.append(scalar)
            }
        }
        return String(out)
    }

    /// Truncate in the middle, keeping both ends.
    ///
    /// Reverse-DNS labels and paths — the dominant name shape in this tool — carry
    /// their distinguishing part at the end, so `prefix(30)` cut off exactly the
    /// bytes that tell `com.adobe.acc.installer.v2` from
    /// `com.adobe.acc.installer.updater`, and marked nothing.
    static func middleTruncate(_ text: String, to width: Int) -> String {
        guard width > 1, text.count > width else { return text }
        let keep = width - 1
        let head = keep - keep / 2
        let tail = keep / 2
        return String(text.prefix(head)) + "\u{2026}" + String(text.suffix(tail))
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

    /// 256-color orange for High, matching the GUI and the HTML report.
    ///
    /// High used to be plain red (31) and Critical bright red (91), distinguished
    /// only by the bright bit — which many terminal themes render nearly
    /// identically, or invert on a light background. That made the two most
    /// important severities unreliable to tell apart while triaging.
    private static let orange = "\u{001B}[38;5;208m"

    private static func riskCodes(_ level: RiskLevel) -> [String] {
        switch level {
        case .critical:      return [bold, brightRed]
        case .high:          return [bold, orange]
        case .medium:        return [yellow]
        case .low:           return [green]
        case .informational: return [dim]
        }
    }

    /// Single-character severity marker, so severity survives a `--no-color` run
    /// or a color-blind reader.
    static func riskMarker(_ level: RiskLevel) -> String {
        switch level {
        case .critical:      return "!!"
        case .high:          return "! "
        case .medium:        return "* "
        case .low:           return "+ "
        case .informational: return "  "
        }
    }

    static func riskStyled(_ level: RiskLevel) -> String {
        let label = level.displayName.uppercased()
        guard colorEnabled else { return label }
        return riskCodes(level).joined() + label + reset
    }

    static func riskBadge(_ level: RiskLevel) -> String {
        let label = riskMarker(level) + level.displayName.uppercased()
        let padded = label.padding(toLength: 15, withPad: " ", startingAt: 0)
        guard colorEnabled else { return padded }
        return riskCodes(level).joined() + padded + reset
    }

    // MARK: - Print Helpers

    /// When set, `write` appends here instead of printing. Used by
    /// `renderTableOutput` to capture a report for writing to a file.
    nonisolated(unsafe) static var capture: ((String) -> Void)?

    /// When true, `write` emits to stderr. Used for diagnostics such as the usage
    /// text, which must never contaminate a redirected stdout.
    nonisolated(unsafe) static var routeOutputToStderr = false

    static func write(_ text: String) {
        if let capture {
            capture(text)
            return
        }
        if routeOutputToStderr {
            writeErr(text)
            return
        }
        print(text)
    }

    /// Run `body` with every `write` routed to stderr.
    static func withStderrOutput(_ body: () -> Void) {
        let previous = routeOutputToStderr
        routeOutputToStderr = true
        defer { routeOutputToStderr = previous }
        body()
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
        write(String(repeating: "-", count: ruleWidth))
    }

    static func sectionHeader(_ title: String) {
        write("")
        write(styled(title, bold, cyan))
        write(String(repeating: "-", count: ruleWidth))
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
        write(String(repeating: "=", count: ruleWidth))
        write("")
        keyValue("Host", sanitize(result.hostname))
        keyValue("OS", sanitize(result.osVersion))
        keyValue("Scanned", result.scanDate.formatted(
            .dateTime.year().month().day().hour().minute().second()
        ))
        keyValue("Duration", String(format: "%.1fs", result.scanDuration))
        write("")
    }

    static func printRiskSummary(_ result: ScanResult, hideApple: Bool) {
        let items = hideApple
            ? result.items.filter { !$0.isVerifiedAppleSoftware }
            : result.items

        let counts: [(RiskLevel, Int)] = RiskLevel.allCases.reversed().map { level in
            (level, items.filter { $0.riskLevel == level }.count)
        }
        let total = items.count
        let thirdParty = items.filter { !$0.source.isApple }.count
        // "Unsigned" and "could not be verified" are different facts. Conflating
        // them is why the GUI and the CLI reported different totals for one machine.
        let unsigned = items.filter { $0.signingInfo?.isSigned == false }.count
        let unverified = items.filter { $0.signingInfo == nil }.count

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
        write("  \(styled("Unverified:", dim))     \(unverified)")
        write("")

        // Coverage. A reader has to know whether "0 items" means clean or blind.
        if result.hasCoverageGaps {
            let blocked = result.categoriesBlockedByPermissions
            write("  " + styled("Coverage:", bold + yellow))
            if !result.ranAsRoot {
                write("    - not run as root; re-run with sudo for full coverage")
            }
            if !blocked.isEmpty {
                let names = blocked.map(\.displayName).sorted().joined(separator: ", ")
                write("    - categories needing privileges: \(names)")
            }
            if !result.hadAuthoritativeLaunchdState {
                write("    - launchd override database unreadable; enabled/disabled "
                      + "state comes from each plist and may be wrong")
            }
            if !result.appliedFilters.isEmpty {
                write("    - filters applied: \(result.appliedFilters.joined(separator: "; "))")
            }
            write("")
        }
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
            write("  \(styled(">", bold)) \(styled(sanitize(item.name), bold))  \(badge)")

            keyValue("Category", item.category.displayName, indent: 4)

            if let config = item.configPath {
                keyValue("Config", sanitize(config), indent: 4)
            }
            if let exec = item.executablePath {
                keyValue("Executable", sanitize(exec), indent: 4)
            }
            if let payload = item.interpretedPayload {
                keyValue("Runs", sanitize(middleTruncate(payload.displayText, to: 120)), indent: 4)
            }
            if let signing = item.signingInfo {
                let status: String
                if !signing.isSigned {
                    status = "No"
                } else if signing.isAppleSigned {
                    status = "Yes (Apple)"
                } else if signing.isNotarized {
                    status = "Yes (notarized)"
                } else if signing.isAdHocSigned {
                    status = "Yes (ad-hoc, no identity)"
                } else {
                    status = "Yes (not notarized)"
                }
                keyValue("Signed", status, indent: 4)
            } else {
                keyValue("Signed", "not verified", indent: 4)
            }
            if !item.riskReasons.isEmpty {
                keyValue("Reasons", sanitize(item.riskReasons[0]), indent: 4)
                for reason in item.riskReasons.dropFirst() {
                    write("                  \(sanitize(reason))")
                }
            }
            // Mitigations are shown under their own heading so a Critical item does
            // not appear to list its own reassurances as warnings.
            if !item.riskMitigations.isEmpty {
                keyValue("Mitigating", sanitize(item.riskMitigations[0]), indent: 4)
                for note in item.riskMitigations.dropFirst() {
                    write("                  \(sanitize(note))")
                }
            }
            if let guidance = item.category.investigationHint {
                keyValue("Next step", guidance, indent: 4)
            }
            write("")
        }
    }

    static func printCategoryTable(_ items: [PersistenceItem], category: PersistenceCategory) {
        guard !items.isEmpty else { return }

        let sorted = items.sorted { $0.riskLevel > $1.riskLevel }
        let countStr = "\(items.count) item\(items.count == 1 ? "" : "s")"

        let title = "-- \(category.displayName) (\(countStr)) "
        write("")
        write(styled(title, bold)
              + String(repeating: "-", count: max(0, ruleWidth - title.count)))
        write("")

        // Column headers
        let hRisk   = "RISK".padding(toLength: 16, withPad: " ", startingAt: 0)
        let hName   = "NAME".padding(toLength: 32, withPad: " ", startingAt: 0)
        let hSigned = "SIGNED".padding(toLength: 10, withPad: " ", startingAt: 0)
        let hSource = "SOURCE"
        write("  \(styled(hRisk + hName + hSigned + hSource, dim))")

        for item in sorted {
            let risk = padded(riskBadge(item.riskLevel), toWidth: 16)
            let name = sanitize(middleTruncate(item.name, to: 30))
                .padding(toLength: 32, withPad: " ", startingAt: 0)
            let signed: String
            if let info = item.signingInfo {
                if !info.isSigned {
                    signed = styled("No", red)
                } else if info.isAppleSigned {
                    signed = "Apple"
                } else if info.isNotarized {
                    signed = "Notarized"
                } else if info.isAdHocSigned {
                    signed = styled("Ad-hoc", yellow)
                } else {
                    signed = styled("Signed", yellow)
                }
            } else {
                // Explicitly "not verified", not an ambiguous dash.
                signed = styled("unverified", dim)
            }
            let signedCol = padded(signed, toWidth: 10)
            let source = sanitize(middleTruncate(item.source.displayName, to: 24))

            write("  \(risk)\(name)\(signedCol)\(source)")
        }
    }

    static func printErrors(_ errors: [ScanError]) {
        guard !errors.isEmpty else { return }

        sectionHeader("SCAN ERRORS (\(errors.count))")
        write("")

        for err in errors {
            let prefix = err.isPermissionDenied
                ? styled("[Permission Denied]", yellow)
                : styled("[Error]", red)
            let scope = err.category?.displayName ?? "Scan"
            write("  \(prefix) \(scope): \(sanitize(err.message))")
            if let path = err.path {
                write("    \(styled(sanitize(path), dim))")
            }
        }
        write("")
    }

    // MARK: - Verbose Item Display

    static func printItemVerbose(_ item: PersistenceItem) {
        let badge = riskStyled(item.riskLevel)
        write("  \(styled(">", bold)) \(styled(sanitize(item.name), bold))  \(badge)")

        keyValue("Category", item.category.displayName, indent: 4)
        if !item.category.attackTechniques.isEmpty {
            keyValue("ATT&CK", item.category.attackTechniques.joined(separator: ", "), indent: 4)
        }

        if let label = item.label {
            keyValue("Label", sanitize(label), indent: 4)
        }
        if let config = item.configPath {
            keyValue("Config", sanitize(config), indent: 4)
        }
        if let exec = item.executablePath {
            keyValue("Executable", sanitize(exec), indent: 4)
        }
        if !item.arguments.isEmpty {
            keyValue("Arguments", sanitize(item.arguments.joined(separator: " ")), indent: 4)
        }
        if let payload = item.interpretedPayload {
            keyValue("Interpreted", sanitize(middleTruncate(payload.displayText, to: 160)),
                     indent: 4)
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
            ? result.items.filter { !$0.isVerifiedAppleSoftware }
            : result.items

        let critical = items.filter { $0.riskLevel == .critical }.count
        let high = items.filter { $0.riskLevel == .high }.count
        let medium = items.filter { $0.riskLevel == .medium }.count
        let low = items.filter { $0.riskLevel == .low }.count
        let info = items.filter { $0.riskLevel == .informational }.count

        // `errors`, `skipped` and `root` are included so a CI job can tell a clean
        // scan from a blind one. Without them a scan that saw nothing looked
        // identical to a scan that found nothing.
        let denied = result.errors.filter(\.isPermissionDenied)
        let skipped = Set(denied.compactMap(\.category)).count
        write(
            "critical=\(critical) high=\(high) medium=\(medium) low=\(low) "
            + "info=\(info) total=\(items.count) "
            + "errors=\(result.errors.count) skipped=\(skipped) "
            + "root=\(result.ranAsRoot ? 1 : 0)"
        )
    }

    // MARK: - Rendered (capturable) table output

    /// Render the full table report into a string.
    ///
    /// `-o report.txt` used to print to the terminal and write nothing at all,
    /// silently, with exit status 0. Rendering to a buffer lets the same output go
    /// to a file.
    static func renderTableOutput(
        _ result: ScanResult,
        originalResult: ScanResult,
        verbose: Bool,
        isRoot: Bool
    ) -> String {
        var buffer: [String] = []
        let previousColor = colorEnabled
        // A file gets plain text; escape sequences in a saved report are noise.
        colorEnabled = false
        capture = { buffer.append($0) }
        defer {
            capture = nil
            colorEnabled = previousColor
        }

        printScanHeader(result)
        printRiskSummary(result, hideApple: false)
        printAttentionItems(result.items)
        sectionHeader("ALL ITEMS BY CATEGORY")
        let grouped = Dictionary(grouping: result.items, by: \.category)
        for category in PersistenceCategory.allCases {
            guard let items = grouped[category], !items.isEmpty else { continue }
            if verbose {
                let countStr = "\(items.count) item\(items.count == 1 ? "" : "s")"
                let title = "-- \(category.displayName) (\(countStr)) "
                write("")
                write(title + String(repeating: "-", count: max(0, ruleWidth - title.count)))
                write("")
                for item in items.sorted(by: { $0.riskLevel > $1.riskLevel }) {
                    printItemVerbose(item)
                }
            } else {
                printCategoryTable(items, category: category)
            }
        }
        printErrors(originalResult.errors)
        printFooter(result, isRoot: isRoot)

        return buffer.joined(separator: "\n") + "\n"
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
        write(String(repeating: "=", count: ruleWidth))

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
        write(styled("EXIT STATUS:", bold))
        write("  0   Scan completed; nothing met --fail-on")
        write("  1   Usage or I/O error")
        write("  2   Findings met or exceeded --fail-on")
        write("  3   Scan could not see everything it needed (only with --fail-on)")
        write("")
    }

    static func printScanHelp() {
        write(styled("USAGE:", bold))
        write("  launchaudit scan [options]")
        write("")
        write(styled("OUTPUT OPTIONS:", bold))
        write("  -f, --format <fmt>    Output format: table, json, csv, html (default: table)")
        write("  -o, --output <path>   Write output to file (format auto-detected from extension)")
        write("  --no-color            Disable colored output (also honors NO_COLOR)")
        write("  --no-progress         Disable progress display")
        write("  -q, --quiet           Machine-readable summary (key=value pairs)")
        write("  --verbose             Show full details for every item")
        write("")
        write(styled("FILTER OPTIONS:", bold))
        write("  --hide-apple          Hide Apple system items (default)")
        write("  --show-apple          Include Apple system items")
        write("  --min-risk <level>    Minimum risk: informational, low, medium, high, critical")
        write("  --unsigned-only       Show only unsigned items")
        write("  --third-party         Show only third-party items")
        write("  -s, --search <query>  Filter items by text search")
        write("  --category <id>       Only scan a specific category (repeatable)")
        write("  --group <name>        Only scan categories in a group (repeatable)")
        write("")
        write(styled("AUTOMATION:", bold))
        write("  --fail-on <level>     Exit 2 when any item is at or above this level")
        write("")
        write(styled("EXIT STATUS:", bold))
        write("  0   Scan completed; nothing met --fail-on")
        write("  1   Usage or I/O error")
        write("  2   Findings met or exceeded --fail-on")
        write("  3   Scan lacked privileges to see everything (only with --fail-on)")
        write("")
        write(styled("EXAMPLES:", bold))
        write("  launchaudit scan")
        write("  launchaudit scan --min-risk high")
        write("  launchaudit scan --format json -o report.json")
        write("  launchaudit scan --unsigned-only --verbose")
        write("  launchaudit scan --category launchdaemons --category launchagents")
        write("  launchaudit scan --group \"System Services\"")
        write("  sudo launchaudit scan --fail-on high --quiet   # CI gate")
        write("")
    }

    static func printExportHelp() {
        write(styled("USAGE:", bold))
        write("  launchaudit export <input.json> [options]")
        write("")
        write(styled("OPTIONS:", bold))
        write("  -f, --format <fmt>    Output format: table, json, csv, html (default: table)")
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
