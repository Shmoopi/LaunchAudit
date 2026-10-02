import Foundation

// MARK: - CLI Configuration

enum CLICommand {
    case scan
    case categories
    case groups
    case export(inputPath: String)
    case version
    case help(subcommand: String?)
}

enum OutputFormat: String {
    case table, json, csv, html

    static func fromExtension(_ path: String) -> OutputFormat? {
        let ext = (path as NSString).pathExtension.lowercased()
        switch ext {
        case "json": return .json
        case "csv":  return .csv
        case "html", "htm": return .html
        case "txt", "text", "log": return .table
        default: return nil
        }
    }
}

struct CLIConfig {
    var command: CLICommand = .scan
    var format: OutputFormat = .table
    var outputPath: String?
    var categoryFilters: [String] = []
    var groupFilters: [String] = []
    var minRisk: RiskLevel?
    var hideApple: Bool = true
    var unsignedOnly: Bool = false
    var thirdPartyOnly: Bool = false
    var searchQuery: String?
    var noProgress: Bool = false
    var quiet: Bool = false
    var verbose: Bool = false
    /// Exit with status 2 when any item meets or exceeds this level, so a scan can
    /// gate a CI job. Previously the CLI always exited 0 and the README worked
    /// around it by grepping the `--quiet` line.
    var failOn: RiskLevel?

    /// Human-readable description of every filter applied, stamped into the
    /// report so a filtered export is not mistaken for a full clean scan.
    var filterDescriptions: [String] {
        var out: [String] = []
        if !categoryFilters.isEmpty {
            out.append("categories: \(categoryFilters.joined(separator: ", "))")
        }
        if !groupFilters.isEmpty {
            out.append("groups: \(groupFilters.joined(separator: ", "))")
        }
        if let minRisk { out.append("minimum risk: \(minRisk.rawValue)") }
        if hideApple { out.append("Apple-signed system items hidden") }
        if unsignedOnly { out.append("unsigned only") }
        if thirdPartyOnly { out.append("third-party only") }
        if let searchQuery { out.append("search: \(searchQuery)") }
        return out
    }
}

// MARK: - Argument Parsing

enum CLIError: Error {
    case unknownCommand(String)
    case unknownOption(String)
    case missingValue(String)
    case invalidValue(option: String, value: String, expected: String)
    case fileNotFound(String)
    case exportError(String)

    var message: String {
        switch self {
        case .unknownCommand(let cmd):
            return "unknown command '\(cmd)'"
        case .unknownOption(let opt):
            return "unknown option '\(opt)'"
        case .missingValue(let opt):
            return "option '\(opt)' requires a value"
        case .invalidValue(let opt, let val, let expected):
            return "invalid value '\(val)' for '\(opt)' (expected: \(expected))"
        case .fileNotFound(let path):
            return "file not found: \(path)"
        case .exportError(let msg):
            return "export failed: \(msg)"
        }
    }

    var showUsage: Bool {
        switch self {
        case .unknownCommand, .unknownOption: return true
        default: return false
        }
    }
}

enum CLIParser {

    static func parse(_ argv: [String]) throws -> CLIConfig {
        let args = Array(argv.dropFirst()) // drop executable name
        var config = CLIConfig()
        var index = 0

        // Handle bare --help / -h / --version / -v before command parsing
        if let first = args.first {
            if first == "--help" || first == "-h" {
                let sub = args.count > 1 && !args[1].hasPrefix("-") ? args[1] : nil
                config.command = .help(subcommand: sub)
                return config
            }
            if first == "--version" || first == "-v" {
                config.command = .version
                return config
            }
        }

        // Parse command (first non-option argument)
        if let first = args.first, !first.hasPrefix("-") {
            switch first.lowercased() {
            case "scan":
                config.command = .scan
                index = 1
            case "categories", "cats":
                config.command = .categories
                index = 1
            case "groups":
                config.command = .groups
                index = 1
            case "export":
                guard args.count > 1 else {
                    throw CLIError.missingValue("export <input.json>")
                }
                config.command = .export(inputPath: args[1])
                index = 2
            case "version":
                config.command = .version
                return config
            case "help":
                let sub = args.count > 1 && !args[1].hasPrefix("-") ? args[1] : nil
                config.command = .help(subcommand: sub)
                return config
            default:
                throw CLIError.unknownCommand(first)
            }
        }

        // Parse options
        while index < args.count {
            let arg = args[index]

            switch arg {
            case "--help", "-h":
                let sub: String?
                if case .scan = config.command { sub = "scan" }
                else if case .export = config.command { sub = "export" }
                else if case .categories = config.command { sub = "categories" }
                else { sub = nil }
                config.command = .help(subcommand: sub)
                return config

            case "--version", "-v":
                config.command = .version
                return config

            case "--format", "-f":
                let val = try requireValue(args: args, index: &index, option: arg)
                guard let fmt = OutputFormat(rawValue: val.lowercased()) else {
                    throw CLIError.invalidValue(
                        option: arg, value: val,
                        expected: "table, json, csv, html"
                    )
                }
                config.format = fmt

            case "--output", "-o":
                let val = try requireValue(args: args, index: &index, option: arg)
                config.outputPath = val
                // Auto-detect format from extension if not explicitly set
                if let detected = OutputFormat.fromExtension(val),
                   !args.contains("--format"), !args.contains("-f") {
                    config.format = detected
                }

            case "--category":
                let val = try requireValue(args: args, index: &index, option: arg)
                config.categoryFilters.append(val)

            case "--group":
                let val = try requireValue(args: args, index: &index, option: arg)
                config.groupFilters.append(val)

            case "--min-risk":
                let val = try requireValue(args: args, index: &index, option: arg)
                guard let level = RiskLevel(rawValue: val.lowercased()) else {
                    throw CLIError.invalidValue(
                        option: arg, value: val,
                        expected: "informational, low, medium, high, critical"
                    )
                }
                config.minRisk = level

            case "--show-apple":
                config.hideApple = false

            case "--hide-apple":
                config.hideApple = true

            case "--unsigned-only":
                config.unsignedOnly = true

            case "--third-party":
                config.thirdPartyOnly = true

            case "--search", "-s":
                let val = try requireValue(args: args, index: &index, option: arg)
                config.searchQuery = val

            case "--no-progress":
                config.noProgress = true

            case "--no-color":
                Terminal.colorEnabled = false

            case "--quiet", "-q":
                config.quiet = true
                config.noProgress = true

            case "--verbose":
                config.verbose = true

            case "--fail-on":
                let val = try requireValue(args: args, index: &index, option: arg)
                guard let level = RiskLevel(rawValue: val.lowercased()) else {
                    throw CLIError.invalidValue(
                        option: arg, value: val,
                        expected: "informational, low, medium, high, critical"
                    )
                }
                config.failOn = level

            default:
                throw CLIError.unknownOption(arg)
            }

            index += 1
        }

        return config
    }

    private static func requireValue(args: [String], index: inout Int, option: String) throws -> String {
        index += 1
        guard index < args.count else {
            throw CLIError.missingValue(option)
        }
        return args[index]
    }
}

// MARK: - Command Execution

enum CLIRunner {

    /// Run the command and return the process exit status.
    ///
    /// The status used to be computed and dropped: every successful run exited 0
    /// regardless of what was found, which is why the README had to grep the
    /// `--quiet` line and call `exit 1` by hand to gate a CI job.
    @discardableResult
    static func execute(_ config: CLIConfig) async throws -> Int32 {
        switch config.command {
        case .scan:
            return try await executeScan(config)
        case .categories:
            executeCategories(config)
        case .groups:
            executeGroups()
        case .export(let inputPath):
            try executeExport(inputPath: inputPath, config: config)
        case .version:
            Terminal.printVersion()
        case .help(let sub):
            executeHelp(subcommand: sub)
        }
        return 0
    }

    // MARK: - Scan

    static let isRunningAsRoot = getuid() == 0

    @discardableResult
    private static func executeScan(_ config: CLIConfig) async throws -> Int32 {
        // Resolve category filters
        let allowedCategories = try resolveCategories(config)

        // Show banner for table output
        if config.format == .table && !config.quiet {
            Terminal.writeErr("LaunchAudit v\(Terminal.appVersion) -- macOS Persistence Auditor")
            if !isRunningAsRoot {
                Terminal.writeErr("")
                Terminal.warning("not running as root -- some system locations may be inaccessible")
                Terminal.writeErr("  Run with sudo for a full scan: sudo launchaudit scan")
            }
            Terminal.writeErr("")
        }

        // Only run the scanners the user asked for. `--category` used to run all
        // 36 and filter afterwards, so a targeted scan cost the same as a full one.
        let options = ScanOptions.headless(categories: allowedCategories)

        let coordinator = await ScanCoordinator()
        let result: ScanResult

        if config.noProgress {
            if !config.quiet && config.format == .table {
                Terminal.writeErr("Scanning...")
            }
            result = await coordinator.performFullScan(options: options)
        } else {
            // Progress goes to stderr, so it is shown for every output format —
            // a 30-second JSON scan used to look like a hang.
            result = await runScanWithProgress(coordinator, options: options)
        }

        // Filter results
        let filteredResult = filterResult(
            result, config: config, allowedCategories: allowedCategories
        )

        // Output results
        try outputResult(filteredResult, originalResult: result, config: config)

        return exitCode(for: filteredResult, config: config)
    }

    /// Exit status contract:
    ///   0 — scan completed and nothing met `--fail-on`
    ///   1 — usage or I/O error (raised as a thrown `CLIError`)
    ///   2 — findings met or exceeded `--fail-on`
    ///   3 — the scan could not see everything it needed to (only with `--fail-on`)
    private static func exitCode(for result: ScanResult, config: CLIConfig) -> Int32 {
        guard let threshold = config.failOn else { return 0 }
        if result.items.contains(where: { $0.riskLevel >= threshold }) { return 2 }
        // A clean result from a blind scan is not a pass.
        if !result.errors.filter(\.isPermissionDenied).isEmpty { return 3 }
        return 0
    }

    private static func runScanWithProgress(
        _ coordinator: ScanCoordinator,
        options: ScanOptions
    ) async -> ScanResult {
        let scanTask = Task { @MainActor in
            await coordinator.performFullScan(options: options)
        }

        // Render progress until the scan task finishes. Keyed off the task rather
        // than off `phase == .complete`, so a scan that fails to reach the
        // terminal phase cannot spin here forever.
        let reporter = Task {
            var lastText = ""
            while !Task.isCancelled {
                let prog = await coordinator.progress
                let text = prog.statusText
                if text != lastText {
                    Terminal.progress(text)
                    lastText = text
                }
                try? await Task.sleep(for: .milliseconds(150))
            }
        }

        let result = await scanTask.value
        reporter.cancel()
        Terminal.clearProgress()
        return result
    }

    private static func resolveCategories(_ config: CLIConfig) throws -> Set<PersistenceCategory>? {
        var allowed = Set<PersistenceCategory>()

        // Resolve --category flags
        for catID in config.categoryFilters {
            let needle = catID.lowercased()
            // Accept the exact camelCase id, a case-insensitive id, or the display
            // name with or without spaces. `--category launchdaemons` used to fail
            // because the id is `launchDaemons` and the display name is
            // "Launch Daemons" — neither matches a bare lowercase word.
            if let cat = PersistenceCategory(rawValue: catID) {
                allowed.insert(cat)
            } else if let cat = PersistenceCategory.allCases.first(where: {
                $0.rawValue.lowercased() == needle
                    || $0.displayName.lowercased() == needle
                    || $0.displayName.lowercased().replacingOccurrences(of: " ", with: "")
                        == needle
            }) {
                allowed.insert(cat)
            } else {
                throw CLIError.invalidValue(
                    option: "--category", value: catID,
                    expected: "a valid category ID (use 'launchaudit categories' to list)"
                )
            }
        }

        // Resolve --group flags
        for groupName in config.groupFilters {
            if let group = CategoryGroup(rawValue: groupName) {
                allowed.formUnion(group.categories)
            } else if let group = CategoryGroup.allCases.first(where: {
                let raw = $0.rawValue.lowercased()
                let needle = groupName.lowercased()
                // "Deprecated / Legacy" should also match "deprecated/legacy".
                return raw == needle
                    || raw.replacingOccurrences(of: " ", with: "") ==
                        needle.replacingOccurrences(of: " ", with: "")
            }) {
                allowed.formUnion(group.categories)
            } else {
                throw CLIError.invalidValue(
                    option: "--group", value: groupName,
                    expected: "a valid group name (use 'launchaudit groups' to list)"
                )
            }
        }

        return allowed.isEmpty ? nil : allowed
    }

    private static func filterResult(
        _ result: ScanResult,
        config: CLIConfig,
        allowedCategories: Set<PersistenceCategory>?
    ) -> ScanResult {
        var items = result.items

        // Category filter (applied post-scan since scanners run on all categories)
        if let allowed = allowedCategories {
            items = items.filter { allowed.contains($0.category) }
        }

        // Minimum risk first, so an explicit risk floor is never silently
        // overridden by the Apple filter below.
        if let minRisk = config.minRisk {
            items = items.filter { $0.riskLevel >= minRisk }
        }

        // Hide Apple-signed system noise — but never hide a high or critical
        // finding. "Hide Apple-signed" means "hide the boring OS rows", not
        // "suppress serious findings that happen to look Apple".
        if config.hideApple {
            items = items.filter { !$0.isVerifiedAppleSoftware || $0.riskLevel >= .high }
        }

        // Unsigned only
        if config.unsignedOnly {
            items = items.filter { $0.signingInfo?.isSigned != true }
        }

        // Third-party only
        if config.thirdPartyOnly {
            items = items.filter { !$0.source.isApple }
        }

        // Search filter
        if let query = config.searchQuery?.lowercased(), !query.isEmpty {
            items = items.filter { item in
                item.name.lowercased().contains(query)
                || (item.label?.lowercased().contains(query) ?? false)
                || (item.configPath?.lowercased().contains(query) ?? false)
                || (item.executablePath?.lowercased().contains(query) ?? false)
                || item.source.displayName.lowercased().contains(query)
            }
        }

        // Keep errors that are not attributable to a category, plus those for the
        // categories still in scope.
        var errors = result.errors
        if let allowed = allowedCategories {
            errors = errors.filter { error in
                guard let category = error.category else { return true }
                return allowed.contains(category)
            }
        }

        // `filtered(items:describedBy:)` preserves toolVersion, ranAsRoot and the
        // rest, and records which filters produced this view.
        var filteredResult = result.filtered(
            items: items, describedBy: config.filterDescriptions
        )
        filteredResult = ScanResult(
            schemaVersion: filteredResult.schemaVersion,
            toolVersion: filteredResult.toolVersion,
            scanDate: filteredResult.scanDate,
            hostname: filteredResult.hostname,
            osVersion: filteredResult.osVersion,
            items: filteredResult.items,
            errors: errors,
            scanDuration: filteredResult.scanDuration,
            ranAsRoot: filteredResult.ranAsRoot,
            scannedCategories: allowedCategories ?? filteredResult.scannedCategories,
            hadAuthoritativeLaunchdState: filteredResult.hadAuthoritativeLaunchdState,
            appliedFilters: filteredResult.appliedFilters
        )
        return filteredResult
    }

    private static func outputResult(
        _ result: ScanResult,
        originalResult: ScanResult,
        config: CLIConfig
    ) throws {
        switch config.format {
        case .table:
            if config.quiet {
                Terminal.printQuiet(result, hideApple: false) // already filtered
            } else if let path = config.outputPath {
                // `-o report.txt` used to print to the terminal and write nothing,
                // silently, with exit status 0.
                let text = Terminal.renderTableOutput(
                    result, originalResult: originalResult,
                    verbose: config.verbose, isRoot: isRunningAsRoot
                )
                try writeOutput(Data(text.utf8), to: path)
            } else {
                printTableOutput(result, originalResult: originalResult, config: config)
            }

        case .json:
            if config.quiet {
                Terminal.writeErr("note: --quiet has no effect with --format json")
            }
            let data = try JSONExporter().export(result)
            try writeOutput(data, to: config.outputPath)

        case .csv:
            let csv = CSVExporter().export(result)
            try writeOutput(Data(csv.utf8), to: config.outputPath)

        case .html:
            let html = HTMLExporter().export(result)
            try writeOutput(Data(html.utf8), to: config.outputPath)
        }
    }

    private static func printTableOutput(
        _ result: ScanResult,
        originalResult: ScanResult,
        config: CLIConfig
    ) {
        Terminal.printScanHeader(result)
        Terminal.printRiskSummary(result, hideApple: false)
        Terminal.printAttentionItems(result.items)

        // Group items by category
        let grouped = Dictionary(grouping: result.items, by: \.category)

        Terminal.sectionHeader("ALL ITEMS BY CATEGORY")

        if config.verbose {
            // Verbose: full detail per item
            for category in PersistenceCategory.allCases {
                guard let items = grouped[category], !items.isEmpty else { continue }

                let sorted = items.sorted { $0.riskLevel > $1.riskLevel }
                let countStr = "\(items.count) item\(items.count == 1 ? "" : "s")"
                Terminal.write("")
                Terminal.write(Terminal.styled(
                    "-- \(category.displayName) (\(countStr)) ",
                    "\u{001B}[1m"
                ) + String(repeating: "-", count: max(0, 50 - category.displayName.count)))
                Terminal.write("")

                for item in sorted {
                    Terminal.printItemVerbose(item)
                }
            }
        } else {
            // Compact: table view per category
            for category in PersistenceCategory.allCases {
                guard let items = grouped[category], !items.isEmpty else { continue }
                Terminal.printCategoryTable(items, category: category)
            }
        }

        // Always show errors from the original (unfiltered) result
        Terminal.printErrors(originalResult.errors)

        // Footer
        Terminal.printFooter(result, isRoot: isRunningAsRoot)
    }

    private static func writeOutput(_ data: Data, to path: String?) throws {
        guard let path else {
            if let str = String(data: data, encoding: .utf8) {
                Terminal.write(str)
            }
            return
        }

        let expanded = (path as NSString).expandingTildeInPath

        // A report can name every persistence mechanism on the machine, so it is
        // created 0600 rather than at the default umask, and the write refuses to
        // follow a symlink — under `sudo` that would otherwise be an arbitrary
        // root-write primitive.
        let fd = open(expanded, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0o600)
        guard fd >= 0 else {
            throw CLIError.exportError(
                "cannot write \(expanded): \(String(cString: strerror(errno)))"
            )
        }
        defer { close(fd) }

        var written = 0
        try data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            while written < data.count {
                let n = write(fd, base.advanced(by: written), data.count - written)
                if n <= 0 {
                    throw CLIError.exportError(
                        "short write to \(expanded): \(String(cString: strerror(errno)))"
                    )
                }
                written += n
            }
        }
        Terminal.writeErr("Written to \(expanded)")
    }

    // MARK: - Categories

    private static func executeCategories(_ config: CLIConfig) {
        // Check for --group filter
        let groupFilter: CategoryGroup?
        if let groupName = config.groupFilters.first {
            groupFilter = CategoryGroup(rawValue: groupName)
                ?? CategoryGroup.allCases.first { $0.rawValue.lowercased() == groupName.lowercased() }
        } else {
            groupFilter = nil
        }

        Terminal.printCategoryList(group: groupFilter)
    }

    // MARK: - Groups

    private static func executeGroups() {
        Terminal.printGroupList()
    }

    // MARK: - Export

    private static func executeExport(inputPath: String, config: CLIConfig) throws {
        let expandedPath = (inputPath as NSString).expandingTildeInPath
        guard FileManager.default.fileExists(atPath: expandedPath) else {
            throw CLIError.fileNotFound(inputPath)
        }

        let data = try Data(contentsOf: URL(fileURLWithPath: expandedPath))
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let result: ScanResult
        do {
            result = try decoder.decode(ScanResult.self, from: data)
        } catch {
            throw CLIError.exportError("failed to parse JSON: \(error.localizedDescription)")
        }

        switch config.format {
        case .table:
            printTableOutput(result, originalResult: result, config: config)

        case .json:
            let exported = try JSONExporter().export(result)
            try writeOutput(exported, to: config.outputPath)

        case .csv:
            let csv = CSVExporter().export(result)
            try writeOutput(Data(csv.utf8), to: config.outputPath)

        case .html:
            let html = HTMLExporter().export(result)
            try writeOutput(Data(html.utf8), to: config.outputPath)
        }
    }

    // MARK: - Help

    private static func executeHelp(subcommand: String?) {
        switch subcommand?.lowercased() {
        case "scan":
            Terminal.printScanHelp()
        case "export":
            Terminal.printExportHelp()
        case "categories", "cats":
            Terminal.printCategoriesHelp()
        default:
            Terminal.printUsage()
        }
    }
}
