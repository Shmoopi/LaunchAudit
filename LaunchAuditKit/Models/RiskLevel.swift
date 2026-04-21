import Foundation
import SwiftUI

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

    public var color: Color {
        switch self {
        case .informational: return .secondary
        case .low: return .green
        case .medium: return .yellow
        case .high: return .orange
        case .critical: return .red
        }
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
}
