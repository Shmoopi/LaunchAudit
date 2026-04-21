import XCTest
@testable import LaunchAudit

final class RiskAnalyzerTests: XCTestCase {

    let analyzer = RiskAnalyzer()

    // MARK: - Signing Trust

    func testAppleSignedItemIsInformational() {
        var item = makeItem(category: .launchDaemons, configPath: "/System/Library/LaunchDaemons/test.plist")
        item.signingInfo = SigningInfo(
            isSigned: true,
            isAppleSigned: true,
            isNotarized: true,
            teamIdentifier: nil,
            signingAuthority: ["Apple Root CA"]
        )
        let result = analyzer.analyze(item)
        XCTAssertEqual(result.riskLevel, .informational)
    }

    func testAppleSignedOutsideSystemIsLow() {
        var item = makeItem(category: .launchDaemons, configPath: "/Library/LaunchDaemons/com.apple.test.plist")
        item.signingInfo = SigningInfo(
            isSigned: true,
            isAppleSigned: true,
            isNotarized: true
        )
        let result = analyzer.analyze(item)
        XCTAssertEqual(result.riskLevel, .low)
    }

    func testNotarizedItemIsCappedAtLow() {
        var item = makeItem(
            category: .launchDaemons,
            executablePath: "/Library/LaunchDaemons/com.example.daemon"
        )
        item.signingInfo = SigningInfo(
            isSigned: true,
            isNotarized: true,
            teamIdentifier: "TEAM123"
        )
        let result = analyzer.analyze(item)
        XCTAssertEqual(result.riskLevel, .low,
            "Notarized items should generally have a low risk rating")
    }

    func testSignedNotNotarizedIsMedium() {
        var item = makeItem(category: .launchAgents, executablePath: "/usr/local/bin/test")
        item.signingInfo = SigningInfo(
            isSigned: true,
            isNotarized: false,
            teamIdentifier: "TEAM456"
        )
        let result = analyzer.analyze(item)
        XCTAssertGreaterThanOrEqual(result.riskLevel, .medium)
        XCTAssert(result.riskReasons.contains { $0.contains("not notarized") })
    }

    func testAdHocSignedIsHigh() {
        var item = makeItem(category: .launchAgents, executablePath: "/usr/local/bin/test")
        item.signingInfo = SigningInfo(
            isSigned: false,
            isAdHocSigned: true
        )
        let result = analyzer.analyze(item)
        XCTAssertGreaterThanOrEqual(result.riskLevel, .high)
        XCTAssert(result.riskReasons.contains { $0.contains("Ad-hoc") })
    }

    func testUnsignedItemIsHigh() {
        var item = makeItem(category: .launchAgents, executablePath: "/usr/local/bin/test")
        item.signingInfo = .unsigned
        let result = analyzer.analyze(item)
        XCTAssertGreaterThanOrEqual(result.riskLevel, .high)
        XCTAssert(result.riskReasons.contains { $0.contains("Unsigned") })
    }

    // MARK: - Mechanism Severity

    func testDylibInjectionIsCritical() {
        let item = makeItem(category: .dylibInjection, riskLevel: .medium)
        let result = analyzer.analyze(item)
        XCTAssertEqual(result.riskLevel, .critical)
    }

    func testDeprecatedMechanismEscalates() {
        let item = makeItem(category: .loginHooks, riskLevel: .medium)
        let result = analyzer.analyze(item)
        XCTAssertGreaterThanOrEqual(result.riskLevel, .high)
        XCTAssert(result.riskReasons.contains { $0.contains("deprecated") })
    }

    func testLaunchDaemonMechanismIsHigh() {
        let item = makeItem(category: .launchDaemons)
        let result = analyzer.analyze(item)
        XCTAssertGreaterThanOrEqual(result.riskLevel, .high)
        XCTAssert(result.riskReasons.contains { $0.contains("root") })
    }

    func testLoginItemMechanismIsLow() {
        let item = makeItem(category: .loginItems)
        let result = analyzer.analyze(item)
        // loginItems mechanism is low, no signing → no signing penalty
        // (no executable path, so signing dimension is informational)
        XCTAssertLessThanOrEqual(result.riskLevel, .low)
    }

    func testReopenAtLoginIsLow() {
        let item = makeItem(category: .reopenAtLogin)
        let result = analyzer.analyze(item)
        XCTAssertLessThanOrEqual(result.riskLevel, .low)
    }

    func testInputManagersIsCritical() {
        let item = PersistenceItem(
            category: .inputMethods,
            name: "EvilInputManager",
            rawMetadata: ["Deprecated": .bool(true)]
        )
        let result = analyzer.analyze(item)
        XCTAssertEqual(result.riskLevel, .critical)
        XCTAssert(result.riskReasons.contains { $0.contains("InputManagers") })
    }

    // MARK: - Execution Context

    func testNonNotarizedRootBootIsHigh() {
        var item = makeItem(
            category: .launchDaemons,
            executablePath: "/Library/LaunchDaemons/com.example.daemon"
        )
        item.signingInfo = SigningInfo(
            isSigned: true,
            isNotarized: false,
            teamIdentifier: "TEAM789"
        )
        // Recreate with boot context and system owner (mimics a real daemon)
        let daemonItem = PersistenceItem(
            category: .launchDaemons,
            name: "com.example.daemon",
            executablePath: "/Library/LaunchDaemons/com.example.daemon",
            runContext: .boot,
            owner: .system,
            signingInfo: item.signingInfo
        )
        let result = analyzer.analyze(daemonItem)
        XCTAssertGreaterThanOrEqual(result.riskLevel, .high,
            "Non-notarized root items running at startup should be high risk")
        XCTAssert(result.riskReasons.contains { $0.contains("Non-notarized") && $0.contains("root") })
    }

    func testNotarizedRootBootIsCappedLow() {
        let item = PersistenceItem(
            category: .launchDaemons,
            name: "com.example.daemon",
            executablePath: "/Library/LaunchDaemons/com.example.daemon",
            runContext: .boot,
            owner: .system,
            signingInfo: SigningInfo(
                isSigned: true,
                isNotarized: true,
                teamIdentifier: "TEAM123"
            )
        )
        let result = analyzer.analyze(item)
        XCTAssertEqual(result.riskLevel, .low,
            "Notarized root boot items should be capped at low")
    }

    // MARK: - Location

    func testWorldWritablePathIsCritical() {
        var item = makeItem(category: .cronJobs, executablePath: "/tmp/evil.sh")
        item.signingInfo = .unsigned
        let result = analyzer.analyze(item)
        XCTAssertEqual(result.riskLevel, .critical)
        XCTAssert(result.riskReasons.contains { $0.contains("world-writable") })
    }

    func testWorldWritableBypassesNotarizationCap() {
        var item = makeItem(category: .cronJobs, executablePath: "/tmp/suspicious")
        item.signingInfo = SigningInfo(
            isSigned: true,
            isNotarized: true,
            teamIdentifier: "TEAM000"
        )
        let result = analyzer.analyze(item)
        XCTAssertEqual(result.riskLevel, .critical,
            "World-writable location should override notarization trust capping")
    }

    func testDylibInjectionBypassesNotarizationCap() {
        var item = makeItem(category: .dylibInjection)
        item.signingInfo = SigningInfo(
            isSigned: true,
            isNotarized: true,
            teamIdentifier: "TEAM000"
        )
        let result = analyzer.analyze(item)
        XCTAssertEqual(result.riskLevel, .critical,
            "DYLD injection should override notarization trust capping")
    }

    // MARK: - Script-Based Categories

    func testShellProfileNotPenalizedForUnsigned() {
        // Use /etc/profile (non-hidden) to test signing exemption in isolation —
        // hidden dot-files like .zshrc correctly trigger location escalation separately.
        let item = PersistenceItem(
            category: .shellProfiles,
            name: "profile",
            configPath: "/etc/profile",
            executablePath: "/etc/profile",
            runContext: .login,
            owner: .system,
            signingInfo: .unsigned  // scripts can't be signed
        )
        let result = analyzer.analyze(item)
        // Shell profiles shouldn't be penalized for being unsigned (they're text files)
        // Mechanism severity is medium; signing should be informational for script categories
        XCTAssertLessThanOrEqual(result.riskLevel, .medium)
        XCTAssertFalse(result.riskReasons.contains { $0.contains("Unsigned") },
            "Script-based items should not be flagged as unsigned binaries")
    }

    func testShellProfileWithSuspiciousPatternsStaysHigh() {
        let item = PersistenceItem(
            category: .shellProfiles,
            name: ".zshrc",
            configPath: "/Users/testuser/.zshrc",
            executablePath: "/Users/testuser/.zshrc",
            runContext: .login,
            owner: .user("testuser"),
            signingInfo: .unsigned,
            riskLevel: .high,
            riskReasons: ["Downloads and pipes to bash"]
        )
        let result = analyzer.analyze(item)
        XCTAssertGreaterThanOrEqual(result.riskLevel, .high,
            "Scanner-flagged suspicious shell profiles should remain high risk")
    }

    // MARK: - Scanner-Set Risk Integration

    func testScannerRiskReasonsPreserved() {
        let item = PersistenceItem(
            category: .pamModules,
            name: "pam_evil.so",
            executablePath: "/usr/local/lib/pam/pam_evil.so",
            riskLevel: .high,
            riskReasons: ["Non-standard PAM module binary"]
        )
        let result = analyzer.analyze(item)
        XCTAssertGreaterThanOrEqual(result.riskLevel, .high)
        XCTAssert(result.riskReasons.contains { $0.contains("Non-standard PAM") })
    }

    func testDefaultMediumRiskDoesNotInflate() {
        // Items with default .medium riskLevel but no explicit riskReasons
        // should not be inflated by the scanner's default
        let item = PersistenceItem(
            category: .reopenAtLogin,
            name: "Calculator",
            riskLevel: .medium  // default from scanner, no reasons
        )
        let result = analyzer.analyze(item)
        XCTAssertLessThanOrEqual(result.riskLevel, .low,
            "Default scanner risk without reasons should not inflate the final level")
    }

    // MARK: - Source Attribution (unchanged behavior)

    func testAppleSignedSourceIsApple() {
        var item = makeItem(category: .launchDaemons)
        item.signingInfo = SigningInfo(
            isSigned: true,
            isAppleSigned: true,
            isNotarized: true
        )
        let result = analyzer.analyze(item)
        XCTAssertEqual(result.source, .apple)
    }

    func testThirdPartySignedSourceExtractsDeveloper() {
        var item = makeItem(category: .launchAgents)
        item.signingInfo = SigningInfo(
            isSigned: true,
            isNotarized: true,
            teamIdentifier: "TEAM123",
            signingAuthority: ["Developer ID Application: Example Corp (TEAM123)"]
        )
        let result = analyzer.analyze(item)
        if case .thirdParty(let name) = result.source {
            XCTAssertEqual(name, "Example Corp")
        } else {
            XCTFail("Expected thirdParty source with developer name")
        }
    }

    // MARK: - Helpers

    private func makeItem(
        category: PersistenceCategory,
        configPath: String? = nil,
        executablePath: String? = nil,
        riskLevel: RiskLevel = .medium
    ) -> PersistenceItem {
        PersistenceItem(
            category: category,
            name: "Test Item",
            configPath: configPath,
            executablePath: executablePath,
            riskLevel: riskLevel
        )
    }
}

// MARK: - RiskClassifier Unit Tests

final class RiskClassifierTests: XCTestCase {

    let classifier = RiskClassifier()

    // MARK: - Signing Trust Dimension

    func testSigningTrust_appleSigned() {
        let signing = SigningInfo(isSigned: true, isAppleSigned: true, isNotarized: true)
        let (level, _) = classifier.classifySigningTrust(signing, hasExecutable: true, category: .launchDaemons)
        XCTAssertEqual(level, .informational)
    }

    func testSigningTrust_notarized() {
        let signing = SigningInfo(isSigned: true, isNotarized: true, teamIdentifier: "TEAM")
        let (level, reasons) = classifier.classifySigningTrust(signing, hasExecutable: true, category: .launchAgents)
        XCTAssertEqual(level, .low)
        XCTAssert(reasons.contains { $0.contains("TEAM") })
    }

    func testSigningTrust_signedNotNotarized() {
        let signing = SigningInfo(isSigned: true, isNotarized: false, teamIdentifier: "TEAM")
        let (level, reasons) = classifier.classifySigningTrust(signing, hasExecutable: true, category: .launchAgents)
        XCTAssertEqual(level, .medium)
        XCTAssert(reasons.contains { $0.contains("not notarized") })
    }

    func testSigningTrust_unsigned() {
        let (level, reasons) = classifier.classifySigningTrust(.unsigned, hasExecutable: true, category: .launchAgents)
        XCTAssertEqual(level, .high)
        XCTAssert(reasons.contains { $0.contains("Unsigned") })
    }

    func testSigningTrust_noExecutable() {
        let (level, _) = classifier.classifySigningTrust(nil, hasExecutable: false, category: .launchAgents)
        XCTAssertEqual(level, .informational)
    }

    func testSigningTrust_scriptCategory_unsignedIsInformational() {
        let (level, reasons) = classifier.classifySigningTrust(.unsigned, hasExecutable: true, category: .shellProfiles)
        XCTAssertEqual(level, .informational)
        XCTAssertFalse(reasons.contains { $0.contains("Unsigned") })
    }

    func testSigningTrust_scriptCategory_nilIsInformational() {
        let (level, _) = classifier.classifySigningTrust(nil, hasExecutable: true, category: .periodicTasks)
        XCTAssertEqual(level, .informational)
    }

    // MARK: - Mechanism Severity Dimension

    func testMechanism_dylibIsCritical() {
        let (level, _) = classifier.classifyMechanismSeverity(.dylibInjection)
        XCTAssertEqual(level, .critical)
    }

    func testMechanism_launchDaemonsIsHigh() {
        let (level, _) = classifier.classifyMechanismSeverity(.launchDaemons)
        XCTAssertEqual(level, .high)
    }

    func testMechanism_kernelExtensionsIsHigh() {
        let (level, _) = classifier.classifyMechanismSeverity(.kernelExtensions)
        XCTAssertEqual(level, .high)
    }

    func testMechanism_pamModulesIsHigh() {
        let (level, _) = classifier.classifyMechanismSeverity(.pamModules)
        XCTAssertEqual(level, .high)
    }

    func testMechanism_launchAgentsIsMedium() {
        let (level, _) = classifier.classifyMechanismSeverity(.launchAgents)
        XCTAssertEqual(level, .medium)
    }

    func testMechanism_loginItemsIsLow() {
        let (level, _) = classifier.classifyMechanismSeverity(.loginItems)
        XCTAssertEqual(level, .low)
    }

    func testMechanism_spotlightIsInformational() {
        let (level, _) = classifier.classifyMechanismSeverity(.spotlightImporters)
        XCTAssertEqual(level, .informational)
    }

    func testMechanism_loginHooksEscalated() {
        let (level, reasons) = classifier.classifyMechanismSeverity(.loginHooks)
        XCTAssertEqual(level, .high)
        XCTAssert(reasons.contains { $0.contains("deprecated") })
    }

    func testMechanism_startupItemsEscalated() {
        let (level, _) = classifier.classifyMechanismSeverity(.startupItems)
        XCTAssertEqual(level, .high)
    }

    // MARK: - Execution Context Dimension

    func testContext_rootBootNonNotarized() {
        let (level, reasons) = classifier.classifyExecutionContext(
            runContext: .boot, owner: .system, signing: SigningInfo(isSigned: true)
        )
        XCTAssertEqual(level, .high)
        XCTAssert(reasons.contains { $0.contains("Non-notarized") })
    }

    func testContext_rootBootNotarized() {
        let signing = SigningInfo(isSigned: true, isNotarized: true)
        let (level, _) = classifier.classifyExecutionContext(
            runContext: .boot, owner: .system, signing: signing
        )
        XCTAssertEqual(level, .medium)
    }

    func testContext_rootBootApple() {
        let signing = SigningInfo(isSigned: true, isAppleSigned: true, isNotarized: true)
        let (level, _) = classifier.classifyExecutionContext(
            runContext: .boot, owner: .system, signing: signing
        )
        XCTAssertEqual(level, .informational)
    }

    func testContext_userLogin() {
        let (level, _) = classifier.classifyExecutionContext(
            runContext: .login, owner: .user("test"), signing: nil
        )
        XCTAssertEqual(level, .low)
    }

    func testContext_onDemand() {
        let (level, _) = classifier.classifyExecutionContext(
            runContext: .onDemand, owner: .system, signing: nil
        )
        XCTAssertEqual(level, .informational)
    }

    func testContext_alwaysRunningRootNonNotarized() {
        let (level, reasons) = classifier.classifyExecutionContext(
            runContext: .always, owner: .system, signing: SigningInfo(isSigned: true)
        )
        XCTAssertEqual(level, .high)
        XCTAssert(reasons.contains { $0.contains("always-running") })
    }

    // MARK: - Content Signals Dimension

    func testContent_inputManagerDeprecated() {
        let (level, reasons) = classifier.classifyContentSignals(
            category: .inputMethods,
            rawMetadata: ["Deprecated": .bool(true)]
        )
        XCTAssertEqual(level, .critical)
        XCTAssert(reasons.contains { $0.contains("InputManagers") })
    }

    func testContent_normalInputMethod() {
        let (level, _) = classifier.classifyContentSignals(
            category: .inputMethods,
            rawMetadata: [:]
        )
        XCTAssertEqual(level, .informational)
    }

    // MARK: - Full Classification Integration

    func testClassify_notarizedDaemonIsCappedLow() {
        let item = PersistenceItem(
            category: .launchDaemons,
            name: "com.example.daemon",
            executablePath: "/Library/LaunchDaemons/com.example.daemon",
            runContext: .boot,
            owner: .system,
            signingInfo: SigningInfo(isSigned: true, isNotarized: true, teamIdentifier: "TEAM")
        )
        let (level, _) = classifier.classify(item)
        XCTAssertEqual(level, .low)
    }

    func testClassify_unsignedDaemonIsHighOrAbove() {
        let item = PersistenceItem(
            category: .launchDaemons,
            name: "com.suspicious.daemon",
            executablePath: "/Library/LaunchDaemons/com.suspicious.daemon",
            runContext: .boot,
            owner: .system,
            signingInfo: .unsigned
        )
        let (level, _) = classifier.classify(item)
        XCTAssertGreaterThanOrEqual(level, .high)
    }

    func testClassify_notarizedLoginItemIsLow() {
        let item = PersistenceItem(
            category: .loginItems,
            name: "MyApp",
            executablePath: "/Applications/MyApp.app/Contents/MacOS/MyApp",
            runContext: .login,
            owner: .user("test"),
            signingInfo: SigningInfo(isSigned: true, isNotarized: true, teamIdentifier: "TEAM")
        )
        let (level, _) = classifier.classify(item)
        XCTAssertEqual(level, .low)
    }

    func testClassify_allDimensions_reasonsCollected() {
        let item = PersistenceItem(
            category: .launchDaemons,
            name: "Test",
            executablePath: "/Library/LaunchDaemons/test",
            runContext: .boot,
            owner: .system,
            signingInfo: SigningInfo(isSigned: true, isNotarized: false, teamIdentifier: "TEAM"),
            riskLevel: .medium,
            riskReasons: ["Scanner-detected issue"]
        )
        let (_, reasons) = classifier.classify(item)
        // Should contain reasons from signing, mechanism, context, and scanner
        XCTAssert(reasons.contains { $0.contains("not notarized") })
        XCTAssert(reasons.contains { $0.contains("root") })
        XCTAssert(reasons.contains { $0.contains("Non-notarized") })
        XCTAssert(reasons.contains { $0.contains("Scanner-detected") })
    }
}
