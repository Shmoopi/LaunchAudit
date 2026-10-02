import Foundation

public struct ScanResult: Codable, Sendable {
    /// Version of this report's structure. Bumped when a change would break an
    /// existing consumer; new optional fields do not require a bump.
    public static let currentSchemaVersion = 2

    public let schemaVersion: Int
    /// Version of LaunchAudit that produced the report.
    public let toolVersion: String
    public let scanDate: Date
    public let hostname: String
    public let osVersion: String
    public let items: [PersistenceItem]
    public let errors: [ScanError]
    public let scanDuration: TimeInterval
    /// Whether the scan had root privileges. Without it, whole categories are
    /// skipped — a reader needs to know that before trusting "0 items".
    public let ranAsRoot: Bool
    /// Categories this scan actually covered.
    public let scannedCategories: Set<PersistenceCategory>
    /// Whether launchd's override database was readable, i.e. whether `isEnabled`
    /// reflects launchd's real state or just the plist key.
    public let hadAuthoritativeLaunchdState: Bool
    /// Filters applied to produce this report, if any. A filtered export is
    /// otherwise indistinguishable from a full clean scan.
    public let appliedFilters: [String]

    public init(
        schemaVersion: Int = ScanResult.currentSchemaVersion,
        toolVersion: String = LaunchAuditVersion.current,
        scanDate: Date = Date(),
        hostname: String = ProcessInfo.processInfo.hostName,
        osVersion: String = ProcessInfo.processInfo.operatingSystemVersionString,
        items: [PersistenceItem],
        errors: [ScanError],
        scanDuration: TimeInterval,
        ranAsRoot: Bool = false,
        scannedCategories: Set<PersistenceCategory> = Set(PersistenceCategory.allCases),
        hadAuthoritativeLaunchdState: Bool = false,
        appliedFilters: [String] = []
    ) {
        self.schemaVersion = schemaVersion
        self.toolVersion = toolVersion
        self.scanDate = scanDate
        self.hostname = hostname
        self.osVersion = osVersion
        self.items = items
        self.errors = errors
        self.scanDuration = scanDuration
        self.ranAsRoot = ranAsRoot
        self.scannedCategories = scannedCategories
        self.hadAuthoritativeLaunchdState = hadAuthoritativeLaunchdState
        self.appliedFilters = appliedFilters
    }

    /// Copy with a different item set, preserving provenance and recording which
    /// filters produced it.
    public func filtered(
        items newItems: [PersistenceItem],
        describedBy filters: [String]
    ) -> ScanResult {
        ScanResult(
            schemaVersion: schemaVersion,
            toolVersion: toolVersion,
            scanDate: scanDate,
            hostname: hostname,
            osVersion: osVersion,
            items: newItems,
            errors: errors,
            scanDuration: scanDuration,
            ranAsRoot: ranAsRoot,
            scannedCategories: scannedCategories,
            hadAuthoritativeLaunchdState: hadAuthoritativeLaunchdState,
            appliedFilters: appliedFilters + filters
        )
    }

    // MARK: - Computed Summaries

    public var itemsByCategory: [PersistenceCategory: [PersistenceItem]] {
        Dictionary(grouping: items, by: \.category)
    }

    public var itemsByRisk: [RiskLevel: [PersistenceItem]] {
        Dictionary(grouping: items, by: \.riskLevel)
    }

    public func count(of level: RiskLevel) -> Int {
        items.filter { $0.riskLevel == level }.count
    }

    public var criticalCount: Int { count(of: .critical) }
    public var highCount: Int { count(of: .high) }
    public var mediumCount: Int { count(of: .medium) }
    public var lowCount: Int { count(of: .low) }

    public var thirdPartyItems: [PersistenceItem] {
        items.filter { !$0.source.isApple }
    }

    /// Items with no valid signature.
    ///
    /// "Unverified" is a third state and is counted separately — conflating it
    /// with unsigned is why the GUI and the CLI used to report different totals
    /// for the same machine.
    public var unsignedItems: [PersistenceItem] {
        items.filter { $0.signingInfo?.isSigned == false }
    }

    /// Items whose signature could not be checked at all.
    public var unverifiedItems: [PersistenceItem] {
        items.filter { $0.signingInfo == nil }
    }

    /// Categories that produced a permission error, so the reader knows which
    /// results are incomplete rather than clean.
    public var categoriesBlockedByPermissions: Set<PersistenceCategory> {
        Set(errors.filter(\.isPermissionDenied).compactMap(\.category))
    }

    /// True when anything prevented full coverage.
    public var hasCoverageGaps: Bool {
        !errors.isEmpty || !ranAsRoot
    }

    // MARK: - Decoding

    private enum CodingKeys: String, CodingKey {
        case schemaVersion, toolVersion, scanDate, hostname, osVersion
        case items, errors, scanDuration, ranAsRoot, scannedCategories
        case hadAuthoritativeLaunchdState, appliedFilters
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try c.decodeIfPresent(Int.self, forKey: .schemaVersion) ?? 1
        toolVersion = try c.decodeIfPresent(String.self, forKey: .toolVersion) ?? "unknown"
        scanDate = try c.decode(Date.self, forKey: .scanDate)
        hostname = try c.decodeIfPresent(String.self, forKey: .hostname) ?? "unknown"
        osVersion = try c.decodeIfPresent(String.self, forKey: .osVersion) ?? "unknown"
        items = try c.decodeIfPresent([PersistenceItem].self, forKey: .items) ?? []
        errors = try c.decodeIfPresent([ScanError].self, forKey: .errors) ?? []
        scanDuration = try c.decodeIfPresent(TimeInterval.self, forKey: .scanDuration) ?? 0
        ranAsRoot = try c.decodeIfPresent(Bool.self, forKey: .ranAsRoot) ?? false
        scannedCategories = try c.decodeIfPresent(
            Set<PersistenceCategory>.self, forKey: .scannedCategories
        ) ?? Set(PersistenceCategory.allCases)
        hadAuthoritativeLaunchdState = try c.decodeIfPresent(
            Bool.self, forKey: .hadAuthoritativeLaunchdState
        ) ?? false
        appliedFilters = try c.decodeIfPresent([String].self, forKey: .appliedFilters) ?? []
    }
}

public struct ScanError: Codable, Sendable, Identifiable, Hashable {
    public let id: UUID
    /// `nil` for errors that are not attributable to one category.
    public let category: PersistenceCategory?
    public let path: String?
    public let message: String
    public let isPermissionDenied: Bool

    public init(
        id: UUID = UUID(),
        category: PersistenceCategory?,
        path: String? = nil,
        message: String,
        isPermissionDenied: Bool = false
    ) {
        self.id = id
        self.category = category
        self.path = path
        self.message = message
        self.isPermissionDenied = isPermissionDenied
    }

    private enum CodingKeys: String, CodingKey {
        case id, category, path, message, isPermissionDenied
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        category = try c.decodeIfPresent(PersistenceCategory.self, forKey: .category)
        path = try c.decodeIfPresent(String.self, forKey: .path)
        message = try c.decode(String.self, forKey: .message)
        isPermissionDenied = try c.decodeIfPresent(
            Bool.self, forKey: .isPermissionDenied
        ) ?? false
    }
}

/// Single source of truth for the shipped version string.
public enum LaunchAuditVersion {
    public static let current: String = {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
            ?? "1.2.0"
    }()
}
