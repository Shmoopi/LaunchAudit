import Foundation

/// Severity assigned to a persistence item.
///
/// Deliberately free of any UI framework import — presentation (colors, symbols,
/// ANSI styling) lives with the presentation layer so the scanning library can be
/// used headlessly.
public enum RiskLevel: String, Codable, CaseIterable, Comparable, Identifiable, Hashable, Sendable {
    case informational
    case low
    case medium
    case high
    case critical

    public var id: String { rawValue }

    public var displayName: String {
        rawValue.capitalized
    }

    public var sortOrder: Int {
        switch self {
        case .informational: return 0
        case .low: return 1
        case .medium: return 2
        case .high: return 3
        case .critical: return 4
        }
    }

    public static func < (lhs: RiskLevel, rhs: RiskLevel) -> Bool {
        lhs.sortOrder < rhs.sortOrder
    }

    /// Escalate risk by one level.
    public var escalated: RiskLevel {
        switch self {
        case .informational: return .low
        case .low: return .medium
        case .medium: return .high
        case .high: return .critical
        case .critical: return .critical
        }
    }

    /// Reduce risk by one level.
    public var demoted: RiskLevel {
        switch self {
        case .critical: return .high
        case .high: return .medium
        case .medium: return .low
        case .low: return .informational
        case .informational: return .informational
        }
    }
}
