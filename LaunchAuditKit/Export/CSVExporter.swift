import Foundation

public struct CSVExporter: Sendable {

    public init() {}

    public func export(_ result: ScanResult) -> String {
        var lines: [String] = []

        // Header
        lines.append([
            "Category", "Name", "Label", "Risk Level", "Status",
            "Signed", "Notarized", "Team ID", "Source",
            "Executable Path", "Config Path", "Run Context",
            "Owner", "Arguments", "Risk Reasons",
            "Created", "Modified"
        ].map { escapeCSV($0) }.joined(separator: ","))

        // Data rows
        for item in result.items {
            let fields: [String] = [
                item.category.displayName,
                item.name,
                item.label ?? "",
                item.riskLevel.displayName,
                item.isEnabled ? "Enabled" : "Disabled",
                item.signingInfo?.isSigned == true ? "Yes" : (item.signingInfo != nil ? "No" : ""),
                item.signingInfo?.isNotarized == true ? "Yes" : "",
                item.signingInfo?.teamIdentifier ?? "",
                item.source.displayName,
                item.executablePath ?? "",
                item.configPath ?? "",
                item.runContext.rawValue,
                item.owner.displayName,
                item.arguments.joined(separator: " "),
                item.riskReasons.joined(separator: "; "),
                item.timestamps.created?.formatted(.iso8601) ?? "",
                item.timestamps.modified?.formatted(.iso8601) ?? ""
            ]
            lines.append(fields.map { escapeCSV($0) }.joined(separator: ","))
        }

        return lines.joined(separator: "\n")
    }

    private func escapeCSV(_ value: String) -> String {
        if value.contains(",") || value.contains("\"") || value.contains("\n") {
            return "\"\(value.replacingOccurrences(of: "\"", with: "\"\""))\""
        }
        return value
    }
}
