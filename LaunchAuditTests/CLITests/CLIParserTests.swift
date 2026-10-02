import XCTest
@testable import LaunchAudit

/// Tests for argument parsing and the exit-status contract.
///
/// `CLIParser.parse` is a pure `[String] -> CLIConfig` function and had no tests at
/// all, despite owning every flag the tool exposes.
final class CLIParserTests: XCTestCase {

    private func parse(_ args: String...) throws -> CLIConfig {
        // argv[0] is the executable name.
        try CLIParser.parse(["launchaudit"] + args)
    }

    // MARK: - Commands

    func testDefaultsToScan() throws {
        let config = try parse()
        guard case .scan = config.command else {
            return XCTFail("expected .scan, got \(config.command)")
        }
    }

    func testRecognizesEachCommand() throws {
        guard case .categories = try parse("categories").command else {
            return XCTFail("categories")
        }
        guard case .categories = try parse("cats").command else { return XCTFail("cats") }
        guard case .groups = try parse("groups").command else { return XCTFail("groups") }
        guard case .version = try parse("version").command else { return XCTFail("version") }
        guard case .export(let path) = try parse("export", "scan.json").command else {
            return XCTFail("export")
        }
        XCTAssertEqual(path, "scan.json")
    }

    func testUnknownCommandThrowsAndShowsUsage() {
        XCTAssertThrowsError(try parse("scna")) { error in
            guard let cliError = error as? CLIError else { return XCTFail("wrong type") }
            XCTAssertTrue(cliError.showUsage)
            XCTAssertTrue(cliError.message.contains("scna"))
        }
    }

    func testUnknownOptionThrows() {
        XCTAssertThrowsError(try parse("scan", "--formt", "csv")) { error in
            guard let cliError = error as? CLIError else { return XCTFail("wrong type") }
            XCTAssertTrue(cliError.showUsage)
        }
    }

    func testMissingValueThrows() {
        XCTAssertThrowsError(try parse("scan", "--min-risk"))
        XCTAssertThrowsError(try parse("export"))
    }

    // MARK: - Formats and output

    func testFormatFlagAndShortForm() throws {
        XCTAssertEqual(try parse("scan", "--format", "json").format, .json)
        XCTAssertEqual(try parse("scan", "-f", "csv").format, .csv)
        XCTAssertEqual(try parse("scan", "--format", "HTML").format, .html)
    }

    func testInvalidFormatThrows() {
        XCTAssertThrowsError(try parse("scan", "--format", "yaml"))
    }

    func testOutputExtensionInfersFormat() throws {
        XCTAssertEqual(try parse("scan", "-o", "r.json").format, .json)
        XCTAssertEqual(try parse("scan", "-o", "r.csv").format, .csv)
        XCTAssertEqual(try parse("scan", "-o", "r.html").format, .html)
        // A text extension maps to the table renderer rather than being ignored:
        // `-o report.txt` used to print to the terminal and write nothing at all.
        XCTAssertEqual(try parse("scan", "-o", "r.txt").format, .table)
    }

    func testExplicitFormatBeatsExtension() throws {
        let config = try parse("scan", "--format", "json", "-o", "r.csv")
        XCTAssertEqual(config.format, .json)
        XCTAssertEqual(config.outputPath, "r.csv")
    }

    // MARK: - Filters

    func testRiskFilterIsCaseInsensitive() throws {
        XCTAssertEqual(try parse("scan", "--min-risk", "HIGH").minRisk, .high)
        XCTAssertEqual(try parse("scan", "--min-risk", "critical").minRisk, .critical)
    }

    func testInvalidRiskThrows() {
        XCTAssertThrowsError(try parse("scan", "--min-risk", "severe"))
    }

    func testAppleFilterDefaultsToHiddenAndCanBeToggled() throws {
        XCTAssertTrue(try parse("scan").hideApple)
        XCTAssertFalse(try parse("scan", "--show-apple").hideApple)
        XCTAssertTrue(try parse("scan", "--show-apple", "--hide-apple").hideApple)
    }

    func testRepeatableCategoryAndGroupFlags() throws {
        let config = try parse(
            "scan", "--category", "launchDaemons", "--category", "cronJobs",
            "--group", "Extensions"
        )
        XCTAssertEqual(config.categoryFilters, ["launchDaemons", "cronJobs"])
        XCTAssertEqual(config.groupFilters, ["Extensions"])
    }

    func testShortFlagsAreAccepted() throws {
        XCTAssertEqual(try parse("scan", "-s", "updater").searchQuery, "updater")
        XCTAssertTrue(try parse("scan", "-q").quiet)
        // --quiet implies --no-progress so the two cannot fight.
        XCTAssertTrue(try parse("scan", "-q").noProgress)
    }

    // MARK: - Automation

    func testFailOnParsesRiskLevel() throws {
        XCTAssertEqual(try parse("scan", "--fail-on", "high").failOn, .high)
        XCTAssertNil(try parse("scan").failOn)
    }

    func testInvalidFailOnThrows() {
        XCTAssertThrowsError(try parse("scan", "--fail-on", "nope"))
    }

    // MARK: - Filter provenance

    func testFilterDescriptionsRecordWhatWasApplied() throws {
        let config = try parse(
            "scan", "--min-risk", "high", "--unsigned-only", "--search", "adobe"
        )
        let descriptions = config.filterDescriptions
        XCTAssertTrue(descriptions.contains { $0.contains("high") })
        XCTAssertTrue(descriptions.contains { $0.contains("unsigned") })
        XCTAssertTrue(descriptions.contains { $0.contains("adobe") })
        // Recorded so a filtered export cannot be mistaken for a full clean scan.
        XCTAssertFalse(descriptions.isEmpty)
    }

    // MARK: - Help

    func testHelpFlagsShortCircuit() throws {
        guard case .help(let sub) = try parse("--help").command else {
            return XCTFail("expected help")
        }
        XCTAssertNil(sub)

        guard case .help(let scanSub) = try parse("help", "scan").command else {
            return XCTFail("expected help scan")
        }
        XCTAssertEqual(scanSub, "scan")

        guard case .help(let inline) = try parse("scan", "--help").command else {
            return XCTFail("expected contextual help")
        }
        XCTAssertEqual(inline, "scan")
    }

    func testVersionFlagShortCircuits() throws {
        guard case .version = try parse("--version").command else {
            return XCTFail("expected version")
        }
        guard case .version = try parse("-v").command else { return XCTFail("expected version") }
    }
}

/// Tests for terminal rendering of untrusted text.
final class TerminalSanitizationTests: XCTestCase {

    func testStripsCursorControlSequences() {
        // A crafted launchd Label could erase its own row — and the row above it —
        // from `launchaudit scan` output, hiding itself from the analyst.
        let hostile = "evil\u{1B}[2K\u{1B}[1A\u{1B}[2K"
        let clean = Terminal.sanitize(hostile)
        XCTAssertFalse(clean.contains("\u{1B}"))
        XCTAssertTrue(clean.hasPrefix("evil"))
    }

    func testStripsEightBitControlCharacters() {
        // 8-bit CSI/OSC are just as effective as the ESC-prefixed forms.
        let clean = Terminal.sanitize("a\u{9B}31mb\u{9D}0;titlec")
        XCTAssertFalse(clean.unicodeScalars.contains { (0x80...0x9F).contains($0.value) })
    }

    func testStripsBidiOverrides() {
        // Right-to-left overrides make `evil.plist` render as `tsilp.live`.
        let clean = Terminal.sanitize("evil\u{202E}txt.plist")
        XCTAssertFalse(clean.unicodeScalars.contains { $0.value == 0x202E })
    }

    func testPreservesOrdinaryTextAndTabs() {
        XCTAssertEqual(Terminal.sanitize("com.example.daemon"), "com.example.daemon")
        XCTAssertEqual(Terminal.sanitize("a\tb"), "a\tb")
        XCTAssertEqual(Terminal.sanitize("café ✓"), "café ✓")
    }

    func testMiddleTruncationKeepsBothEnds() {
        // Reverse-DNS labels carry their distinguishing part at the end, so
        // `prefix(30)` cut off exactly the bytes that tell two apart.
        let a = Terminal.middleTruncate("com.adobe.acc.installer.v2", to: 20)
        let b = Terminal.middleTruncate("com.adobe.acc.installer.updater", to: 20)
        XCTAssertNotEqual(a, b)
        XCTAssertTrue(a.contains("\u{2026}"))
        XCTAssertTrue(a.hasPrefix("com."))
        XCTAssertTrue(a.hasSuffix("v2"))
    }

    func testShortTextIsNotTruncated() {
        XCTAssertEqual(Terminal.middleTruncate("short", to: 20), "short")
    }
}
