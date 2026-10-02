import SwiftUI
import AppKit

/// Presentation for `RiskLevel`. Lives in the app layer so `LaunchAuditKit`
/// stays free of UI framework dependencies.
extension RiskLevel {

    /// Fill color for badges, dots and chart marks.
    ///
    /// These are deliberately darker than the generic system accent colors: white
    /// text on `.systemYellow` measures about 1.4:1 and on `.systemOrange` about
    /// 2.1:1, both far below the 4.5:1 minimum for the 11pt text used in badges.
    /// Every pairing below clears 5:1.
    var color: Color {
        switch self {
        case .critical: return Color(red: 0.72, green: 0.11, blue: 0.11)
        case .high: return Color(red: 0.65, green: 0.33, blue: 0.00)
        case .medium: return Color(red: 0.99, green: 0.80, blue: 0.16)
        case .low: return Color(red: 0.13, green: 0.50, blue: 0.20)
        case .informational: return Color(nsColor: .tertiaryLabelColor)
        }
    }

    /// Text/glyph color to use on top of `color`.
    var onColor: Color {
        switch self {
        case .critical, .high, .low: return .white
        case .medium: return Color(red: 0.16, green: 0.12, blue: 0.00)
        case .informational: return Color(nsColor: .labelColor)
        }
    }

    /// A distinct glyph per level.
    ///
    /// Risk must not be encoded by hue alone: the sidebar's colored dots are
    /// indistinguishable to a deuteranopic viewer and vanish in a grayscale print
    /// of an exported report.
    var sfSymbol: String {
        switch self {
        case .critical: return "exclamationmark.octagon.fill"
        case .high: return "exclamationmark.triangle.fill"
        case .medium: return "exclamationmark.circle.fill"
        case .low: return "checkmark.circle.fill"
        case .informational: return "info.circle"
        }
    }

    /// Spoken description for assistive technology.
    var accessibilityDescription: String {
        switch self {
        case .critical: return "Critical risk"
        case .high: return "High risk"
        case .medium: return "Medium risk"
        case .low: return "Low risk"
        case .informational: return "Informational"
        }
    }
}

/// The standard risk badge, used everywhere a level is shown inline.
struct RiskBadge: View {
    let level: RiskLevel
    var compact: Bool = false

    var body: some View {
        Label {
            Text(level.displayName)
        } icon: {
            Image(systemName: level.sfSymbol)
        }
        .labelStyle(.titleAndIcon)
        .font(.caption2.weight(.semibold))
        .foregroundStyle(level.onColor)
        .padding(.horizontal, compact ? 5 : 7)
        .padding(.vertical, 2)
        .background(level.color, in: Capsule())
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(level.accessibilityDescription)
    }
}

/// Compact risk indicator for dense contexts such as the sidebar, where the
/// glyph carries the meaning rather than the color.
struct RiskIndicator: View {
    let level: RiskLevel

    var body: some View {
        Image(systemName: level.sfSymbol)
            .font(.caption2)
            .foregroundStyle(level.color)
            .accessibilityLabel(level.accessibilityDescription)
    }
}
