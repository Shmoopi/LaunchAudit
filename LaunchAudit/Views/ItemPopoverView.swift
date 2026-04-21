import SwiftUI

struct ItemPopoverView: View {
    let item: PersistenceItem
    var onDismiss: (() -> Void)?

    @State private var filePreviewContent: String?

    var body: some View {
        VStack(spacing: 0) {
            // Compact header
            header
                .padding()

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    identitySection
                    pathsSection
                    signingSection
                    riskSection
                    timestampsSection
                    categorySpecificSections
                    rawMetadataSection
                }
                .padding()
            }
        }
        .frame(width: 620, height: 580)
        .background(.ultraThickMaterial, in: RoundedRectangle(cornerRadius: 12))
        .overlay(alignment: .topTrailing) {
            Button { onDismiss?() } label: {
                Image(systemName: "xmark.circle.fill")
                    .font(.title3)
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
            .padding(12)
            .keyboardShortcut(.escape, modifiers: [])
        }
        .shadow(color: .black.opacity(0.3), radius: 30, y: 10)
        .task {
            loadFilePreviewIfNeeded()
        }
    }

    // MARK: - Header

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: item.category.sfSymbol)
                .font(.title2)
                .foregroundStyle(.blue)

            VStack(alignment: .leading, spacing: 4) {
                Text(item.name)
                    .font(.headline)
                    .lineLimit(2)

                HStack(spacing: 6) {
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
    }

    private var actionButtons: some View {
        HStack(spacing: 8) {
            if let path = item.configPath ?? item.executablePath {
                Button {
                    NSWorkspace.shared.selectFile(path, inFileViewerRootedAtPath: "")
                } label: {
                    Label("Reveal in Finder", systemImage: "folder")
                }
                .controlSize(.small)
            }

            Button {
                let info = formatItemInfo()
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(info, forType: .string)
            } label: {
                Label("Copy Info", systemImage: "doc.on.doc")
            }
            .controlSize(.small)
        }
    }

    // MARK: - Standard Sections

    private var identitySection: some View {
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
    }

    private var pathsSection: some View {
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
    }

    @ViewBuilder
    private var signingSection: some View {
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
    }

    @ViewBuilder
    private var riskSection: some View {
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
    }

    private var timestampsSection: some View {
        DetailSection(title: "Timestamps") {
            if let created = item.timestamps.created {
                DetailRow(key: "Created", value: created.formatted(.dateTime))
            }
            if let modified = item.timestamps.modified {
                DetailRow(key: "Modified", value: modified.formatted(.dateTime))
            }
        }
    }

    // MARK: - Category-Specific Sections

    @ViewBuilder
    private var categorySpecificSections: some View {
        switch item.category {
        case .browserExtensions:
            browserExtensionSections
        case .shellProfiles:
            shellProfileSections
        case .launchDaemons, .launchAgents:
            launchServiceSection
        case .cronJobs:
            cronJobSection
        case .kernelExtensions:
            kernelExtensionSection
        case .systemExtensions:
            systemExtensionSection
        case .configurationProfiles:
            configurationProfileSection
        case .appExtensions:
            appExtensionSection
        case .printerPlugins:
            printerPluginSection
        case .loginItems:
            loginItemSection
        default:
            EmptyView()
        }
    }

    // MARK: Browser Extensions

    private var browserExtensionSections: some View {
        Group {
            DetailSection(title: "Extension Details") {
                metadataRowIfPresent("Browser", key: "Browser")
                metadataRowIfPresent("Version", key: "Version")
                metadataRowIfPresent("Manifest Version", key: "ManifestVersion")
                metadataRowIfPresent("Description", key: "Description")
                metadataRowIfPresent("Author", key: "Author")
                metadataRowIfPresent("Homepage", key: "Homepage")
                metadataRowIfPresent("Profile", key: "Profile")
                metadataRowIfPresent("Extension ID", key: "ExtensionID")
                metadataRowIfPresent("Type", key: "Type")
            }

            if hasAnyKey(["Permissions", "HostPermissions", "ContentScriptMatches", "Background"]) {
                DetailSection(title: "Permissions & Access") {
                    commaSplitListIfPresent("Permissions", key: "Permissions")
                    commaSplitListIfPresent("Host Permissions", key: "HostPermissions")
                    commaSplitListIfPresent("Content Scripts", key: "ContentScriptMatches")
                    if let bg = item.rawMetadata["Background"] {
                        DetailRow(key: "Background", value: bg.boolValue == true ? "Active" : bg.displayString)
                    }
                }
            }
        }
    }

    // MARK: Shell Profiles

    @ViewBuilder
    private var shellProfileSections: some View {
        DetailSection(title: "Shell Details") {
            metadataRowIfPresent("Shell Type", key: "ShellType")
            metadataRowIfPresent("Scope", key: "Scope")
        }

        if let content = filePreviewContent {
            DetailSection(title: "File Preview") {
                ScrollView {
                    Text(content)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 200)
            }
        }
    }

    // MARK: Launch Daemons / Launch Agents

    private var launchServiceSection: some View {
        DetailSection(title: "Service Configuration") {
            let keys: [String] = [
                "Label", "Program", "ProgramArguments", "RunAtLoad", "KeepAlive",
                "StartInterval", "StartCalendarInterval", "WatchPaths", "QueueDirectories",
                "MachServices", "Sockets", "WorkingDirectory", "EnvironmentVariables",
                "UserName", "GroupName", "StandardOutPath", "StandardErrorPath",
                "ThrottleInterval", "ProcessType", "LimitLoadToSessionType", "Nice",
                "SoftResourceLimits", "HardResourceLimits"
            ]
            ForEach(keys, id: \.self) { key in
                if let value = item.rawMetadata[key] {
                    metadataRow(label: key, value: value)
                }
            }
        }
    }

    // MARK: Cron Jobs

    private var cronJobSection: some View {
        DetailSection(title: "Schedule Details") {
            metadataRowIfPresent("Schedule", key: "Schedule")
            metadataRowIfPresent("Command", key: "Command")
            metadataRowIfPresent("Type", key: "Type")
        }
    }

    // MARK: Kernel Extensions

    private var kernelExtensionSection: some View {
        DetailSection(title: "Kext Details") {
            metadataRowIfPresent("CFBundleIdentifier", key: "CFBundleIdentifier")
            metadataRowIfPresent("CFBundleVersion", key: "CFBundleVersion")
            metadataRowIfPresent("CFBundleShortVersionString", key: "CFBundleShortVersionString")
            metadataListIfPresent("OSBundleLibraries", key: "OSBundleLibraries")
            metadataRowIfPresent("Loaded", key: "Loaded")
            metadataRowIfPresent("CFBundleGetInfoString", key: "CFBundleGetInfoString")
            metadataRowIfPresent("NSHumanReadableCopyright", key: "NSHumanReadableCopyright")
        }
    }

    // MARK: System Extensions

    private var systemExtensionSection: some View {
        DetailSection(title: "Extension Details") {
            metadataRowIfPresent("Team ID", key: "TeamID")
            metadataRowIfPresent("State", key: "State")
            metadataRowIfPresent("Raw Line", key: "RawLine")
        }
    }

    // MARK: Configuration Profiles

    private var configurationProfileSection: some View {
        DetailSection(title: "Profile Details") {
            metadataRowIfPresent("Identifier", key: "ProfileIdentifier")
            metadataRowIfPresent("Organization", key: "ProfileOrganization")
            metadataRowIfPresent("Description", key: "ProfileDescription")
            metadataRowIfPresent("Type", key: "ProfileType")
            metadataRowIfPresent("Version", key: "ProfileVersion")
            metadataRowIfPresent("Payload Content", key: "PayloadContent")
        }
    }

    // MARK: App Extensions

    private var appExtensionSection: some View {
        DetailSection(title: "Extension Details") {
            if let label = item.label {
                DetailRow(key: "Bundle ID", value: label, copyable: true)
            }
            metadataRowIfPresent("Source", key: "Source")
            metadataRowIfPresent("Registration", key: "RawLine")
        }
    }

    // MARK: Printer Plugins

    private var printerPluginSection: some View {
        DetailSection(title: "Plugin Details") {
            metadataRowIfPresent("Directory", key: "Directory")
            if let label = item.label {
                DetailRow(key: "Bundle ID", value: label, copyable: true)
            }
        }
    }

    // MARK: Login Items

    private var loginItemSection: some View {
        DetailSection(title: "Login Item Details") {
            metadataRowIfPresent("Source", key: "Source")
            metadataRowIfPresent("Hide", key: "Hide")
        }
    }

    // MARK: - Raw Metadata

    @ViewBuilder
    private var rawMetadataSection: some View {
        if !item.rawMetadata.isEmpty {
            DetailSection(title: "Raw Metadata") {
                ForEach(item.rawMetadata.sorted(by: { $0.key < $1.key }), id: \.key) { key, value in
                    rawMetadataRow(key: key, value: value, indent: 0)
                }
            }
        }
    }

    // MARK: - Metadata Helpers

    @ViewBuilder
    private func metadataRowIfPresent(_ label: String, key: String) -> some View {
        if let value = item.rawMetadata[key] {
            metadataRow(label: label, value: value)
        }
    }

    @ViewBuilder
    private func metadataRow(label: String, value: PlistValue) -> some View {
        switch value {
        case .array(let items):
            VStack(alignment: .leading, spacing: 2) {
                HStack(alignment: .top) {
                    Text(label)
                        .foregroundStyle(.secondary)
                        .frame(width: 150, alignment: .trailing)
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(Array(items.enumerated()), id: \.offset) { _, element in
                            Text(element.displayString)
                                .font(.system(.body, design: .monospaced))
                        }
                    }
                    Spacer()
                }
            }
        case .dictionary(let dict):
            VStack(alignment: .leading, spacing: 2) {
                HStack(alignment: .top) {
                    Text(label)
                        .foregroundStyle(.secondary)
                        .frame(width: 150, alignment: .trailing)
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(dict.sorted(by: { $0.key < $1.key }), id: \.key) { k, v in
                            Text("\(k): \(v.displayString)")
                                .font(.system(.body, design: .monospaced))
                        }
                    }
                    Spacer()
                }
            }
        default:
            DetailRow(key: label, value: value.displayString, monospaced: true)
        }
    }

    @ViewBuilder
    private func metadataListIfPresent(_ label: String, key: String) -> some View {
        if let value = item.rawMetadata[key] {
            if let items = value.arrayValue {
                VStack(alignment: .leading, spacing: 2) {
                    HStack(alignment: .top) {
                        Text(label)
                            .foregroundStyle(.secondary)
                            .frame(width: 150, alignment: .trailing)
                        VStack(alignment: .leading, spacing: 2) {
                            ForEach(Array(items.enumerated()), id: \.offset) { _, element in
                                HStack(alignment: .top, spacing: 4) {
                                    Text("\u{2022}")
                                    Text(element.displayString)
                                        .font(.system(.body, design: .monospaced))
                                }
                            }
                        }
                        Spacer()
                    }
                }
            } else if let dict = value.dictionaryValue {
                VStack(alignment: .leading, spacing: 2) {
                    HStack(alignment: .top) {
                        Text(label)
                            .foregroundStyle(.secondary)
                            .frame(width: 150, alignment: .trailing)
                        VStack(alignment: .leading, spacing: 2) {
                            ForEach(dict.sorted(by: { $0.key < $1.key }), id: \.key) { k, v in
                                HStack(alignment: .top, spacing: 4) {
                                    Text("\u{2022}")
                                    Text("\(k): \(v.displayString)")
                                        .font(.system(.body, design: .monospaced))
                                }
                            }
                        }
                        Spacer()
                    }
                }
            } else {
                DetailRow(key: label, value: value.displayString, monospaced: true)
            }
        }
    }

    @ViewBuilder
    private func rawMetadataRow(key: String, value: PlistValue, indent: Int) -> some View {
        switch value {
        case .array(let items):
            VStack(alignment: .leading, spacing: 2) {
                HStack(alignment: .top) {
                    Text(key)
                        .foregroundStyle(.secondary)
                        .frame(width: 150, alignment: .trailing)
                    VStack(alignment: .leading, spacing: 1) {
                        ForEach(Array(items.enumerated()), id: \.offset) { _, element in
                            Text(element.displayString)
                                .font(.system(.caption, design: .monospaced))
                                .padding(.leading, CGFloat(indent * 12))
                        }
                    }
                    Spacer()
                }
            }
        case .dictionary(let dict):
            VStack(alignment: .leading, spacing: 2) {
                HStack(alignment: .top) {
                    Text(key)
                        .foregroundStyle(.secondary)
                        .frame(width: 150, alignment: .trailing)
                    VStack(alignment: .leading, spacing: 1) {
                        ForEach(dict.sorted(by: { $0.key < $1.key }), id: \.key) { k, v in
                            Text("\(k): \(v.displayString)")
                                .font(.system(.caption, design: .monospaced))
                                .padding(.leading, CGFloat(indent * 12))
                        }
                    }
                    Spacer()
                }
            }
        default:
            DetailRow(key: key, value: value.displayString, monospaced: true)
        }
    }

    /// Splits a comma-separated string metadata value into a bulleted list.
    @ViewBuilder
    private func commaSplitListIfPresent(_ label: String, key: String) -> some View {
        if let value = item.rawMetadata[key]?.stringValue {
            let parts = value.components(separatedBy: ", ").filter { !$0.isEmpty }
            if !parts.isEmpty {
                HStack(alignment: .top) {
                    Text(label)
                        .foregroundStyle(.secondary)
                        .frame(width: 150, alignment: .trailing)
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(parts, id: \.self) { part in
                            HStack(alignment: .top, spacing: 4) {
                                Text("\u{2022}")
                                Text(part)
                                    .font(.system(.caption, design: .monospaced))
                            }
                        }
                    }
                    Spacer()
                }
            }
        }
    }

    private func hasAnyKey(_ keys: [String]) -> Bool {
        keys.contains { item.rawMetadata[$0] != nil }
    }

    // MARK: - File Preview Loading

    private func loadFilePreviewIfNeeded() {
        guard item.category == .shellProfiles, let path = item.configPath else { return }
        do {
            let content = try String(contentsOfFile: path, encoding: .utf8)
            let lines = content.components(separatedBy: .newlines)
            let preview = lines.prefix(30).joined(separator: "\n")
            filePreviewContent = preview
        } catch {
            filePreviewContent = nil
        }
    }

    // MARK: - Copy Info

    private func formatItemInfo() -> String {
        var lines: [String] = []
        lines.append("Name: \(item.name)")
        if let label = item.label { lines.append("Label: \(label)") }
        lines.append("Category: \(item.category.displayName)")
        lines.append("Risk: \(item.riskLevel.displayName)")
        if let config = item.configPath { lines.append("Config: \(config)") }
        if let exec = item.executablePath { lines.append("Executable: \(exec)") }
        lines.append("Status: \(item.isEnabled ? "Enabled" : "Disabled")")
        lines.append("Owner: \(item.owner.displayName)")
        lines.append("Source: \(item.source.displayName)")
        lines.append("Run Context: \(item.runContext.rawValue.capitalized)")
        if !item.arguments.isEmpty {
            lines.append("Arguments: \(item.arguments.joined(separator: " "))")
        }
        if let signing = item.signingInfo {
            lines.append("Signed: \(signing.isSigned ? "Yes" : "No")")
            if signing.isSigned {
                lines.append("Notarized: \(signing.isNotarized ? "Yes" : "No")")
                if let team = signing.teamIdentifier {
                    lines.append("Team ID: \(team)")
                }
            }
        }
        if !item.riskReasons.isEmpty {
            lines.append("Risk Reasons:")
            for reason in item.riskReasons {
                lines.append("  - \(reason)")
            }
        }
        return lines.joined(separator: "\n")
    }
}

// MARK: - Overlay Modifier

extension View {
    func itemDetailOverlay(item: Binding<PersistenceItem?>) -> some View {
        modifier(ItemDetailOverlayModifier(item: item))
    }
}

private struct ItemDetailOverlayModifier: ViewModifier {
    @Binding var item: PersistenceItem?

    func body(content: Content) -> some View {
        content.overlay {
            if let presentedItem = item {
                ZStack {
                    // Clickable scrim
                    Color.black.opacity(0.3)
                        .ignoresSafeArea()
                        .onTapGesture { item = nil }

                    ItemPopoverView(item: presentedItem, onDismiss: { item = nil })
                        .transition(.opacity.combined(with: .scale(scale: 0.95)))
                }
                .animation(.easeOut(duration: 0.15), value: item != nil)
            }
        }
    }
}
