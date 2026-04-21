import SwiftUI

struct ItemListView: View {
    @EnvironmentObject var viewModel: ScanViewModel
    let category: PersistenceCategory
    @Binding var selectedItem: PersistenceItem?

    @State private var selectedItemID: PersistenceItem.ID?
    @State private var popoverItem: PersistenceItem?
    // Note: Empty initial value to avoid Swift 6 Sendable warning with KeyPathComparator.
    // Default sort is applied in .onAppear.
    @State private var sortOrder: [KeyPathComparator<PersistenceItem>] = []
    @State private var needsDefaultSort = true

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Category header
            HStack {
                Image(systemName: category.sfSymbol)
                    .font(.title3)
                Text(category.displayName)
                    .font(.title3.bold())
                Text("(\(filteredItems.count) items)")
                    .foregroundStyle(.secondary)
                Spacer()
            }
            .padding()

            if category.description != category.displayName {
                Text(category.description)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal)
                    .padding(.bottom, 8)
            }

            Divider()

            // Items table
            Table(sortedItems, selection: $selectedItemID, sortOrder: $sortOrder) {
                riskColumn
                nameColumn
                statusColumn
                signingColumn
                developerColumn
                pathColumn
            }
            .onChange(of: selectedItemID) { _, newID in
                selectedItem = filteredItems.first { $0.id == newID }
            }
            .contextMenu(forSelectionType: PersistenceItem.ID.self) { ids in
                if let id = ids.first,
                   let item = filteredItems.first(where: { $0.id == id }) {
                    if let path = item.configPath ?? item.executablePath {
                        Button("Reveal in Finder") {
                            NSWorkspace.shared.selectFile(path, inFileViewerRootedAtPath: "")
                        }
                        Button("Copy Path") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(path, forType: .string)
                        }
                    }
                }
            } primaryAction: { ids in
                if let id = ids.first,
                   let item = filteredItems.first(where: { $0.id == id }) {
                    popoverItem = item
                }
            }
            .itemDetailOverlay(item: $popoverItem)
            .onAppear(perform: initializeSortOrderIfNeeded)
        }
    }

    // Warning: "KeyPath does not conform to Sendable" is expected below.
    // This is a known Swift issue (https://github.com/swiftlang/swift/issues/69487).
    // KeyPath is immutable and thread-safe; Apple will add Sendable conformance in a future release.
    private func initializeSortOrderIfNeeded() {
        guard needsDefaultSort else { return }
        needsDefaultSort = false
        sortOrder = [KeyPathComparator(\.riskSortKey, order: .reverse)]
    }

    // MARK: - Table Columns (broken out to help the type checker)

    private var riskColumn: some TableColumnContent<PersistenceItem, KeyPathComparator<PersistenceItem>> {
        TableColumn("Risk", value: \.riskSortKey) { item in
            RiskBadge(level: item.riskLevel)
        }
        .width(min: 60, ideal: 80)
    }

    private var nameColumn: some TableColumnContent<PersistenceItem, KeyPathComparator<PersistenceItem>> {
        TableColumn("Name", value: \.name) { (item: PersistenceItem) in
            VStack(alignment: .leading) {
                Text(item.name)
                    .lineLimit(1)
                if let label = item.label, label != item.name {
                    Text(label)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
        }
        .width(min: 150, ideal: 250)
    }

    private var statusColumn: some TableColumnContent<PersistenceItem, KeyPathComparator<PersistenceItem>> {
        TableColumn("Status", value: \.statusSortKey) { item in
            HStack(spacing: 4) {
                Circle()
                    .fill(item.isEnabled ? .green : .gray)
                    .frame(width: 8, height: 8)
                Text(item.isEnabled ? "Enabled" : "Disabled")
                    .font(.caption)
            }
        }
        .width(min: 70, ideal: 80)
    }

    private var signingColumn: some TableColumnContent<PersistenceItem, KeyPathComparator<PersistenceItem>> {
        TableColumn("Signed", value: \.signingSortKey) { item in
            SigningCellView(signingInfo: item.signingInfo)
        }
        .width(min: 80, ideal: 100)
    }

    private var developerColumn: some TableColumnContent<PersistenceItem, KeyPathComparator<PersistenceItem>> {
        TableColumn("Developer", value: \.developerSortKey) { item in
            Text(item.source.displayName)
                .font(.caption)
                .foregroundStyle(item.source.isApple ? .secondary : .primary)
        }
        .width(min: 80, ideal: 120)
    }

    private var pathColumn: some TableColumnContent<PersistenceItem, KeyPathComparator<PersistenceItem>> {
        TableColumn("Path", value: \.pathSortKey) { item in
            Text(item.configPath ?? item.executablePath ?? "--")
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
        }
        .width(min: 100, ideal: 200)
    }

    private var filteredItems: [PersistenceItem] {
        viewModel.filteredItems(for: category)
    }

    private var sortedItems: [PersistenceItem] {
        filteredItems.sorted(using: sortOrder)
    }
}

// MARK: - Signing Cell

private struct SigningCellView: View {
    let signingInfo: SigningInfo?

    var body: some View {
        if let signing = signingInfo {
            HStack(spacing: 4) {
                Image(systemName: signing.isSigned ? "checkmark.seal.fill" : "xmark.seal.fill")
                    .foregroundStyle(signing.isSigned ? (signing.isNotarized ? .green : .yellow) : .red)
                if signing.isNotarized {
                    Text("Notarized").font(.caption)
                } else if signing.isSigned {
                    Text("Signed").font(.caption)
                } else {
                    Text("Unsigned").font(.caption).foregroundStyle(.red)
                }
            }
        } else {
            Text("--").foregroundStyle(.tertiary)
        }
    }
}

// MARK: - Sort Keys

extension PersistenceItem {
    /// Sort key for risk level (uses sortOrder from RiskLevel).
    var riskSortKey: Int {
        riskLevel.sortOrder
    }

    /// Sort key for enabled/disabled status (enabled sorts above disabled).
    var statusSortKey: Int {
        isEnabled ? 1 : 0
    }

    /// Sort key for signing state: 0 = unknown, 1 = unsigned, 2 = ad-hoc, 3 = signed, 4 = notarized.
    var signingSortKey: Int {
        guard let info = signingInfo else { return 0 }
        if !info.isSigned { return 1 }
        if info.isAdHocSigned { return 2 }
        if info.isNotarized { return 4 }
        return 3
    }

    /// Sort key for developer column.
    var developerSortKey: String {
        source.displayName
    }

    /// Sort key for path column.
    var pathSortKey: String {
        configPath ?? executablePath ?? ""
    }
}

