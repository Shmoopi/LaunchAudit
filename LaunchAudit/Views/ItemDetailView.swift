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
                        // Identifiers and paths must never be hyphenated or wrapped:
                        // SwiftUI's hyphenator rendered `com.sketchy.updater` as
                        // "com.sketchy.up-" / "dater", which is actively misleading
                        // in a tool whose job is reporting exact identifiers.
                        Text(item.name)
                            .font(.title2.bold())
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .textSelection(.enabled)
                            .help(item.name)
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
                        DetailRow(key: "Arguments",
                                  value: item.arguments.joined(separator: " "),
                                  monospaced: true, copyable: true)
                    }
                    if let payload = item.interpretedPayload {
                        // For an interpreter-fronted item this — not the executable —
                        // is the code that runs.
                        DetailRow(key: "Runs", value: payload.displayText,
                                  monospaced: true, copyable: true)
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
                            if !signing.entitlements.isEmpty {
                                DetailRow(
                                    key: "Risky Entitlements",
                                    value: signing.entitlements.joined(separator: "\n"),
                                    monospaced: true
                                )
                            }
                        }
                    }
                }

                // Risk Assessment
                DetailSection(title: "Risk Assessment") {
                    HStack {
                        Text("Risk Level")
                            .foregroundStyle(.secondary)
                        Spacer()
                        RiskBadge(level: item.riskLevel)
                    }

                    if !item.riskReasons.isEmpty {
                        Text("Why this is flagged")
                            .font(.subheadline.weight(.semibold))
                        ForEach(item.riskReasons, id: \.self) { reason in
                            finding(reason, symbol: "exclamationmark.triangle.fill",
                                    tint: item.riskLevel.color)
                        }
                    }

                    // Mitigating facts get their own heading. Concatenating them
                    // into the warning list meant a Critical item appeared to list
                    // its own reassurances as reasons to worry.
                    if !item.riskMitigations.isEmpty {
                        Text("Mitigating factors")
                            .font(.subheadline.weight(.semibold))
                        ForEach(item.riskMitigations, id: \.self) { note in
                            finding(note, symbol: "checkmark.circle.fill", tint: .green)
                        }
                    }

                    if item.riskReasons.isEmpty && item.riskMitigations.isEmpty {
                        Text("Nothing notable was found for this item.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                }

                // What this mechanism is, and what to do next. A verdict with no
                // interpretation left users unable to tell a real finding from noise.
                DetailSection(title: "About This Mechanism") {
                    Text(item.category.description)
                        .font(.callout)
                        .fixedSize(horizontal: false, vertical: true)

                    Text("What's normal")
                        .font(.subheadline.weight(.semibold))
                    Text(item.category.whatIsNormal)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)

                    if let hint = item.category.investigationHint {
                        Text("How to investigate")
                            .font(.subheadline.weight(.semibold))
                        HStack(alignment: .top, spacing: 6) {
                            Text(hint)
                                .font(.system(.callout, design: .monospaced))
                                .textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                            Button {
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(hint, forType: .string)
                            } label: {
                                Image(systemName: "doc.on.doc").font(.caption)
                            }
                            .buttonStyle(.borderless)
                            .help("Copy this command")
                        }
                    }

                    if !item.category.attackTechniques.isEmpty {
                        DetailRow(
                            key: "MITRE ATT&CK",
                            value: item.category.attackTechniques.joined(separator: ", "),
                            copyable: true
                        )
                    }
                }

                if item.signingInfo == nil, item.executablePath != nil {
                    DetailSection(title: "Code Signing") {
                        Text("The signature could not be checked. This is not the same "
                             + "as being unsigned — the file may be unreadable, or may "
                             + "not be a Mach-O binary.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
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
        // No opaque `.background(.background)`: it overrides the translucent
        // material SwiftUI gives an `.inspector`, which is why the panel read as a
        // flat rectangle rather than as part of the window.
    }

    @ViewBuilder
    private func finding(_ text: String, symbol: String, tint: Color) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Image(systemName: symbol)
                .foregroundStyle(tint)
                .font(.caption)
                .accessibilityHidden(true)
            Text(text)
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
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
            lines.append("Findings:")
            for reason in item.riskReasons {
                lines.append("  - \(reason)")
            }
        }
        if !item.riskMitigations.isEmpty {
            lines.append("Mitigating factors:")
            for note in item.riskMitigations {
                lines.append("  - \(note)")
            }
        }
        if !item.category.attackTechniques.isEmpty {
            lines.append("ATT&CK: \(item.category.attackTechniques.joined(separator: ", "))")
        }
        if let hint = item.category.investigationHint {
            lines.append("Next step: \(hint)")
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
        // `LabeledContent` is the native macOS key/value control: it aligns across
        // siblings and adapts to the available width. The previous hardcoded
        // `.frame(width: 150)` left roughly 110pt for the value at the inspector's
        // minimum width, which is what forced paths and bundle identifiers to wrap
        // and hyphenate. It also ignored Dynamic Type entirely.
        LabeledContent {
            HStack(alignment: .firstTextBaseline, spacing: 4) {
                Text(value)
                    .font(monospaced ? .system(.callout, design: .monospaced) : .callout)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)

                if copyable {
                    Button {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(value, forType: .string)
                    } label: {
                        Image(systemName: "doc.on.doc").font(.caption)
                    }
                    .buttonStyle(.borderless)
                    .help("Copy \(key)")
                    .accessibilityLabel("Copy \(key)")
                }
            }
        } label: {
            Text(key)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(key): \(value)")
    }
}
