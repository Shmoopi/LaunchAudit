import SwiftUI

struct ItemDetailView: View {
    let item: PersistenceItem

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // Header
                HStack {
                    Image(systemName: item.category.sfSymbol)
                        .font(.title)
                        .foregroundStyle(.blue)
                    VStack(alignment: .leading) {
                        Text(item.name)
                            .font(.title2.bold())
                        HStack {
                            RiskBadge(level: item.riskLevel)
                            Text(item.category.displayName)
                                .font(.caption)
                                .padding(.horizontal, 8)
                                .padding(.vertical, 2)
                                .background(.blue.opacity(0.1), in: Capsule())
                        }
                    }
                    Spacer()
                    actionButtons
                }

                Divider()

                // Identity Section
                DetailSection(title: "Identity") {
                    if let label = item.label {
                        DetailRow(key: "Label / Bundle ID", value: label)
                    }
                    DetailRow(key: "Category", value: item.category.displayName)
                    DetailRow(key: "Owner", value: item.owner.displayName)
                    DetailRow(key: "Status", value: item.isEnabled ? "Enabled" : "Disabled")
                    DetailRow(key: "Run Context", value: item.runContext.rawValue.capitalized)
                    DetailRow(key: "Source", value: item.source.displayName)
                }

                // Paths Section
                DetailSection(title: "Paths") {
                    if let config = item.configPath {
                        DetailRow(key: "Config", value: config, monospaced: true, copyable: true)
                    }
                    if let exec = item.executablePath {
                        DetailRow(key: "Executable", value: exec, monospaced: true, copyable: true)
                    }
                    if !item.arguments.isEmpty {
                        DetailRow(key: "Arguments", value: item.arguments.joined(separator: " "), monospaced: true)
                    }
                }

                // Signing Section
                if let signing = item.signingInfo {
                    DetailSection(title: "Code Signing") {
                        DetailRow(key: "Signed", value: signing.isSigned ? "Yes" : "No")
                        if signing.isSigned {
                            DetailRow(key: "Notarized", value: signing.isNotarized ? "Yes" : "No")
                            DetailRow(key: "Apple Signed", value: signing.isAppleSigned ? "Yes" : "No")
                            DetailRow(key: "Ad-hoc", value: signing.isAdHocSigned ? "Yes" : "No")
                            if let team = signing.teamIdentifier {
                                DetailRow(key: "Team ID", value: team, copyable: true)
                            }
                            if !signing.signingAuthority.isEmpty {
                                DetailRow(key: "Certificate Chain", value: signing.signingAuthority.joined(separator: "\n"))
                            }
                            if let cdHash = signing.cdHash {
                                DetailRow(key: "CDHash", value: cdHash, monospaced: true, copyable: true)
                            }
                            if let bundleID = signing.bundleIdentifier {
                                DetailRow(key: "Bundle ID (signed)", value: bundleID, copyable: true)
                            }
                        }
                    }
                }

                // Risk Assessment
                if !item.riskReasons.isEmpty {
                    DetailSection(title: "Risk Assessment") {
                        HStack {
                            Text("Risk Level")
                                .foregroundStyle(.secondary)
                            Spacer()
                            RiskBadge(level: item.riskLevel)
                        }
                        ForEach(item.riskReasons, id: \.self) { reason in
                            HStack(alignment: .top) {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .foregroundStyle(item.riskLevel.color)
                                    .font(.caption)
                                Text(reason)
                                    .font(.callout)
                            }
                        }
                    }
                }

                // Timestamps
                DetailSection(title: "Timestamps") {
                    if let created = item.timestamps.created {
                        DetailRow(key: "Created", value: created.formatted(.dateTime))
                    }
                    if let modified = item.timestamps.modified {
                        DetailRow(key: "Modified", value: modified.formatted(.dateTime))
                    }
                }

                // Raw Metadata
                if !item.rawMetadata.isEmpty {
                    DetailSection(title: "Raw Metadata") {
                        ForEach(item.rawMetadata.sorted(by: { $0.key < $1.key }), id: \.key) { key, value in
                            DetailRow(key: key, value: value.displayString, monospaced: true)
                        }
                    }
                }
            }
            .padding()
        }
        .background(.background)
    }

    private var actionButtons: some View {
        HStack {
            if let path = item.configPath ?? item.executablePath {
                Button("Reveal in Finder") {
                    NSWorkspace.shared.selectFile(path, inFileViewerRootedAtPath: "")
                }
            }

            Button("Copy Info") {
                let info = formatItemInfo()
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(info, forType: .string)
            }
        }
    }

    private func formatItemInfo() -> String {
        var lines: [String] = []
        lines.append("Name: \(item.name)")
        if let label = item.label { lines.append("Label: \(label)") }
        lines.append("Category: \(item.category.displayName)")
        lines.append("Risk: \(item.riskLevel.displayName)")
        if let config = item.configPath { lines.append("Config: \(config)") }
        if let exec = item.executablePath { lines.append("Executable: \(exec)") }
        lines.append("Status: \(item.isEnabled ? "Enabled" : "Disabled")")
        lines.append("Source: \(item.source.displayName)")
        if !item.riskReasons.isEmpty {
            lines.append("Risk Reasons:")
            for reason in item.riskReasons {
                lines.append("  - \(reason)")
            }
        }
        return lines.joined(separator: "\n")
    }
}

struct DetailSection<Content: View>: View {
    let title: String
    @ViewBuilder let content: Content

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                content
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        } label: {
            Text(title)
                .font(.headline)
        }
    }
}

struct DetailRow: View {
    let key: String
    let value: String
    var monospaced: Bool = false
    var copyable: Bool = false

    var body: some View {
        HStack(alignment: .top) {
            Text(key)
                .foregroundStyle(.secondary)
                .frame(width: 150, alignment: .trailing)

            if monospaced {
                Text(value)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
            } else {
                Text(value)
                    .textSelection(.enabled)
            }

            if copyable {
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(value, forType: .string)
                } label: {
                    Image(systemName: "doc.on.doc")
                        .font(.caption)
                }
                .buttonStyle(.borderless)
            }

            Spacer()
        }
    }
}
