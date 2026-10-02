import Foundation

public struct CSVExporter: Sendable {

    public init() {}

    public func export(_ result: ScanResult) -> String {
        var lines: [String] = []

        // Header
        lines.append([
            "Stable ID", "Category", "ATT&CK", "Name", "Label", "Risk Level", "Status",
            "Signed", "Notarized", "Ad-hoc", "Team ID", "Source",
            "Executable Path", "Interpreted Payload", "Config Path", "Run Context",
            "Owner", "Arguments", "Risk Reasons", "Mitigating Factors",
            "Risky Entitlements", "Created", "Modified",
        ].map { escapeCSV($0) }.joined(separator: ","))

        // Data rows
        for item in result.items {
            let signing = item.signingInfo
            let fields: [String] = [
                item.stableID,
                item.category.displayName,
                item.category.attackTechniques.joined(separator: " "),
                item.name,
                item.label ?? "",
                item.riskLevel.displayName,
                item.isEnabled ? "Enabled" : "Disabled",
                // Three states, named explicitly. An empty cell for "never verified"
                // was indistinguishable from "no data".
                signing == nil ? "Not verified" : (signing!.isSigned ? "Yes" : "No"),
                signing?.isNotarized == true ? "Yes" : "",
                signing?.isAdHocSigned == true ? "Yes" : "",
                signing?.teamIdentifier ?? "",
                item.source.displayName,
                item.executablePath ?? "",
                item.interpretedPayload?.displayText ?? "",
                item.configPath ?? "",
                item.runContext.rawValue,
                item.owner.displayName,
                item.arguments.joined(separator: " "),
                item.riskReasons.joined(separator: "; "),
                item.riskMitigations.joined(separator: "; "),
                (signing?.entitlements ?? []).joined(separator: "; "),
                item.timestamps.created?.formatted(.iso8601) ?? "",
                item.timestamps.modified?.formatted(.iso8601) ?? "",
            ]
            lines.append(fields.map { escapeCSV($0) }.joined(separator: ","))
        }

        // A UTF-8 BOM so Excel does not mangle non-ASCII names.
        return "\u{FEFF}" + lines.joined(separator: "\r\n") + "\r\n"
    }

    /// Escape a value for CSV, and neutralize spreadsheet formula triggers.
    ///
    /// RFC 4180 quoting alone is not enough. Every text field here originates in a
    /// file an attacker may control — `item.name` is the launchd `Label` — and a
    /// value beginning `=`, `+`, `-`, `@`, tab or CR is executed as a formula when
    /// the report is opened in Excel or Numbers. `=HYPERLINK(...)` exfiltrates the
    /// surrounding rows on a single click; legacy DDE payloads reach code execution.
    /// None of those payloads need to contain a comma or a quote, so they used to be
    /// emitted completely unguarded.
    ///
    /// Prefixing with an apostrophe forces the cell to be read as text.
    func escapeCSV(_ value: String) -> String {
        var escaped = value

        if let first = escaped.unicodeScalars.first,
           "=+-@\t\r".unicodeScalars.contains(first) {
            escaped = "'" + escaped
        }

        // `\r` is included: a bare carriage return splits the row for strict readers.
        if escaped.contains(",") || escaped.contains("\"")
            || escaped.contains("\n") || escaped.contains("\r") {
            return "\"\(escaped.replacingOccurrences(of: "\"", with: "\"\""))\""
        }
        return escaped
    }
}
