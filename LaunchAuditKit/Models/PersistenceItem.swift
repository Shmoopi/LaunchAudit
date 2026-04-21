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
    public let isEnabled: Bool
    public let runContext: RunContext
    public let owner: ItemOwner
    public var signingInfo: SigningInfo?
    public var riskLevel: RiskLevel
    public var riskReasons: [String]
    public let source: ItemSource
    public let timestamps: ItemTimestamps
    public let rawMetadata: [String: PlistValue]

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
        self.source = source
        self.timestamps = timestamps
        self.rawMetadata = rawMetadata
    }
}

extension PersistenceItem {
    /// True when the item is an Apple-provided component — either verified via
    /// code signature or identified by bundle ID / system path when signing
    /// verification isn't possible (e.g., sealed system volume binaries).
    public var isAppleSignedAndNotarized: Bool {
        // If signing verification ran and confirmed Apple-signed + notarized,
        // trust the cryptographic proof.
        if let info = signingInfo {
            if info.isAppleSigned && info.isNotarized {
                return true
            }
            // Signing ran but the binary is NOT Apple-signed — it's third-party
            // even if the label or path looks Apple-ish.
            if info.isSigned && !info.isAppleSigned {
                return false
            }
        }
        // No signing info available (e.g., sealed system volume where
        // SecStaticCode can't read the binary) — fall back to source heuristic.
        return source.isApple
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
