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

    static func execute(_ config: CLIConfig) async throws {
        switch config.command {
        case .scan:
            try await executeScan(config)
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
    }

    // MARK: - Scan

    static let isRunningAsRoot = getuid() == 0

    private static func executeScan(_ config: CLIConfig) async throws {
        // Resolve category filters
        let allowedCategories = try resolveCategories(config)

        // Tell scanners we're headless — skip GUI prompts (e.g., osascript)
        setenv("LAUNCHAUDIT_HEADLESS", "1", 1)

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

        // Run the scan
        let coordinator = await ScanCoordinator()
        let result: ScanResult

        if config.noProgress || config.format != .table {
            // No progress display — just run the scan
            if !config.quiet && config.format == .table {
                Terminal.writeErr("Scanning...")
            }
            result = await coordinator.performFullScan()
        } else {
            // Show live progress on stderr
            result = await runScanWithProgress(coordinator)
        }

        // Filter results
        let filteredResult = filterResult(result, config: config, allowedCategories: allowedCategories)

        // Output results
        try outputResult(filteredResult, originalResult: result, config: config)
    }

    private static func runScanWithProgress(_ coordinator: ScanCoordinator) async -> ScanResult {
        // Start scan in a concurrent task
        let scanTask = Task { @MainActor in
            await coordinator.performFullScan()
        }

        // Poll progress on stderr
        var lastPhase: ScanPhase?
        while true {
            let prog = await coordinator.progress
            if prog.phase != lastPhase || prog.phase == .scanning {
                Terminal.progress(prog.statusText)
                lastPhase = prog.phase
            }
            if prog.phase == .complete { break }

            try? await Task.sleep(for: .milliseconds(150))
        }

        Terminal.clearProgress()

        return await scanTask.value
    }

    private static func resolveCategories(_ config: CLIConfig) throws -> Set<PersistenceCategory>? {
        var allowed = Set<PersistenceCategory>()

        // Resolve --category flags
        for catID in config.categoryFilters {
            if let cat = PersistenceCategory(rawValue: catID) {
                allowed.insert(cat)
            } else if let cat = PersistenceCategory.allCases.first(where: {
                $0.displayName.lowercased() == catID.lowercased()
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
                $0.rawValue.lowercased() == groupName.lowercased()
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

        // Hide Apple-signed items
        if config.hideApple {
            items = items.filter { !$0.isAppleSignedAndNotarized }
        }

        // Minimum risk filter
        if let minRisk = config.minRisk {
            items = items.filter { $0.riskLevel >= minRisk }
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

        // Filter errors to only relevant categories
        var errors = result.errors
        if let allowed = allowedCategories {
            errors = errors.filter { allowed.contains($0.category) }
        }

        return ScanResult(
            scanDate: result.scanDate,
            hostname: result.hostname,
            osVersion: result.osVersion,
            items: items,
            errors: errors,
            scanDuration: result.scanDuration
        )
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
            } else {
                printTableOutput(result, originalResult: originalResult, config: config)
            }

        case .json:
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
        if let path = path {
            let url = URL(fileURLWithPath: (path as NSString).expandingTildeInPath)
            try data.write(to: url)
            Terminal.writeErr("Written to \(url.path)")
        } else {
            if let str = String(data: data, encoding: .utf8) {
                Terminal.write(str)
            }
        }
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
