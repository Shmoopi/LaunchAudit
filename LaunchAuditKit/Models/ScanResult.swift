import Foundation

public struct ScanResult: Codable, Sendable {
    public let scanDate: Date
    public let hostname: String
    public let osVersion: String
    public let items: [PersistenceItem]
    public let errors: [ScanError]
    public let scanDuration: TimeInterval

    public init(
        scanDate: Date = Date(),
        hostname: String = ProcessInfo.processInfo.hostName,
        osVersion: String = ProcessInfo.processInfo.operatingSystemVersionString,
        items: [PersistenceItem],
        errors: [ScanError],
        scanDuration: TimeInterval
    ) {
        self.scanDate = scanDate
        self.hostname = hostname
        self.osVersion = osVersion
        self.items = items
        self.errors = errors
        self.scanDuration = scanDuration
    }

    // MARK: - Computed Summaries

    public var itemsByCategory: [PersistenceCategory: [PersistenceItem]] {
        Dictionary(grouping: items, by: \.category)
    }

    public var itemsByRisk: [RiskLevel: [PersistenceItem]] {
        Dictionary(grouping: items, by: \.riskLevel)
    }

    public var criticalCount: Int { items.filter { $0.riskLevel == .critical }.count }
    public var highCount: Int { items.filter { $0.riskLevel == .high }.count }
    public var mediumCount: Int { items.filter { $0.riskLevel == .medium }.count }
    public var lowCount: Int { items.filter { $0.riskLevel == .low }.count }

    public var thirdPartyItems: [PersistenceItem] {
        items.filter { !$0.source.isApple }
    }

    public var unsignedItems: [PersistenceItem] {
        items.filter { $0.signingInfo?.isSigned == false }
    }
}

public struct ScanError: Codable, Sendable, Identifiable {
    public let id: UUID
    public let category: PersistenceCategory
    public let path: String?
    public let message: String
    public let isPermissionDenied: Bool

    public init(
        id: UUID = UUID(),
        category: PersistenceCategory,
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
}
