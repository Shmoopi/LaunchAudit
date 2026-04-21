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

    /// Classify a persistence item and return the final risk level with reasons.
    public func classify(_ item: PersistenceItem) -> (level: RiskLevel, reasons: [String]) {
        // Evaluate each independent risk dimension
        let signing = classifySigningTrust(
            item.signingInfo,
            hasExecutable: item.executablePath != nil,
            category: item.category
        )
        let mechanism = classifyMechanismSeverity(item.category)
        let context = classifyExecutionContext(
            runContext: item.runContext,
            owner: item.owner,
            signing: item.signingInfo
        )
        let location = classifyLocation(
            configPath: item.configPath,
            executablePath: item.executablePath
        )
        let temporal = classifyTemporalSignals(
            timestamps: item.timestamps,
            configPath: item.configPath
        )
        let content = classifyContentSignals(
            category: item.category,
            rawMetadata: item.rawMetadata
        )

        // Collect all reasons from every dimension
        var allReasons: [String] = []
        allReasons.append(contentsOf: signing.reasons)
        allReasons.append(contentsOf: mechanism.reasons)
        allReasons.append(contentsOf: context.reasons)
        allReasons.append(contentsOf: location.reasons)
        allReasons.append(contentsOf: temporal.reasons)
        allReasons.append(contentsOf: content.reasons)

        // Include scanner-provided reasons (e.g., suspicious shell profile patterns)
        allReasons.append(contentsOf: item.riskReasons)

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
        ]
        if !item.riskReasons.isEmpty {
            dimensionLevels.append(item.riskLevel)
        }

        let rawMax = dimensionLevels.max() ?? .medium

        // Apply trust-based capping
        let finalLevel = applyTrustCapping(
            rawLevel: rawMax,
            signing: item.signingInfo,
            configPath: item.configPath,
            locationLevel: location.level,
            category: item.category
        )

        return (finalLevel, allReasons)
    }

    // MARK: - Dimension: Signing Trust

    /// Categories where the "executable" is a script or text file, not a
    /// compiled Mach-O binary. Code signing is not applicable — unsigned
    /// status is expected and not a risk indicator. Risk for these items
    /// comes from mechanism severity and content analysis instead.
    private static let scriptCategories: Set<PersistenceCategory> = [
        .shellProfiles, .periodicTasks, .rcScripts, .emondRules
    ]

    /// Evaluate risk based on code signing status.
    func classifySigningTrust(
        _ signing: SigningInfo?,
        hasExecutable: Bool,
        category: PersistenceCategory
    ) -> (level: RiskLevel, reasons: [String]) {
        // Script-based items can't be code-signed — don't penalize.
        // If signing somehow reports signed (binary target in a script category),
        // fall through to normal checks.
        if Self.scriptCategories.contains(category) {
            guard let signing = signing, signing.isSigned else {
                return (.informational, [])
            }
        }

        guard let signing = signing else {
            if hasExecutable {
                return (.medium, ["Code signing not verified"])
            }
            return (.informational, [])
        }

        if signing.isAppleSigned {
            return (.informational, [])
        }

        if signing.isSigned && signing.isNotarized {
            var reasons: [String] = []
            if let team = signing.teamIdentifier {
                reasons.append("Signed by team: \(team)")
            }
            return (.low, reasons)
        }

        if signing.isSigned && !signing.isNotarized {
            return (.medium, ["Signed but not notarized"])
        }

        if signing.isAdHocSigned {
            return (.high, ["Ad-hoc signed (no team identity)"])
        }

        if !signing.isSigned {
            return (.high, ["Unsigned binary"])
        }

        return (.medium, [])
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
            reasons.append("Runs as root at system boot")

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
        signing: SigningInfo?
    ) -> (level: RiskLevel, reasons: [String]) {
        let isRoot: Bool = {
            if case .system = owner { return true }
            return false
        }()
        let isNotarized = signing?.isNotarized ?? false
        let isApple = signing?.isAppleSigned ?? false

        // Apple-signed items don't get context escalation
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

    /// Evaluate risk from filesystem location of the config and executable.
    func classifyLocation(
        configPath: String?,
        executablePath: String?
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

        if let config = configPath {
            if PathUtilities.isHidden(config) {
                level = level.escalated
                reasons.append("Hidden config file: \(config)")
            }

            if PathUtilities.isSystemPath(config) && PathUtilities.isWritable(config) {
                level = .critical
                reasons.append("System path writable by current user")
            }
        }

        return (level, reasons)
    }

    // MARK: - Dimension: Temporal Signals

    /// Evaluate risk from file modification timestamps.
    func classifyTemporalSignals(
        timestamps: ItemTimestamps,
        configPath: String?
    ) -> (level: RiskLevel, reasons: [String]) {
        guard let modified = timestamps.modified else {
            return (.informational, [])
        }

        let thirtyDaysAgo = Calendar.current.date(byAdding: .day, value: -30, to: Date())!
        if modified > thirtyDaysAgo {
            if let config = configPath, PathUtilities.isSystemPath(config) {
                return (.medium, [
                    "System file modified recently (\(modified.formatted(.dateTime.month().day())))"
                ])
            }
        }

        return (.informational, [])
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
    private func applyTrustCapping(
        rawLevel: RiskLevel,
        signing: SigningInfo?,
        configPath: String?,
        locationLevel: RiskLevel,
        category: PersistenceCategory
    ) -> RiskLevel {
        guard let signing = signing else { return rawLevel }

        // Hard overrides that bypass trust capping: the danger is not about
        // identity but about location or mechanism.
        let hasHardOverride = locationLevel >= .critical
            || category == .dylibInjection
            || category == .filelessProcesses

        if signing.isAppleSigned {
            if let config = configPath, PathUtilities.isSystemPath(config) {
                return hasHardOverride ? rawLevel : .informational
            }
            return hasHardOverride ? rawLevel : .low
        }

        if signing.isSigned && signing.isNotarized && !hasHardOverride {
            return min(rawLevel, .low)
        }

        return rawLevel
    }
}
