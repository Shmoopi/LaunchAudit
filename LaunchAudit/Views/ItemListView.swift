import SwiftUI

struct ItemListView: View {
    enum Scope: Hashable {
        case everything
        case category(PersistenceCategory)

        var category: PersistenceCategory? {
            if case .category(let value) = self { return value }
            return nil
        }
    }

    @EnvironmentObject var viewModel: ScanViewModel
    let scope: Scope
    @Binding var selectedItem: PersistenceItem?

    @State private var selectedItemIDs: Set<PersistenceItem.ID> = []
    @State private var sortOrder: [ItemComparator] = [ItemComparator(.risk, order: .reverse)]

    var body: some View {
        // Sorted once per render; this used to sort twice (once for the emptiness
        // check, once for the table) on every view-model change.
        let rows = filteredItems.sorted(using: sortOrder)
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()

            if rows.isEmpty {
                emptyState
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                table(rows)
            }
        }
        .onChange(of: selectedItemIDs) { _, ids in
            selectedItem = ids.count == 1
                ? filteredItems.first { ids.contains($0.id) }
                : nil
        }
    }

    // MARK: - Header

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Image(systemName: scope.category?.sfSymbol ?? "list.bullet.rectangle")
                    .font(.title3)
                    .accessibilityHidden(true)
                Text(scope.category?.displayName ?? "All Items")
                    .font(.title3.bold())
                // Correct pluralization: this used to render "(1 items)".
                Text("^[\(filteredItems.count) item](inflect: true)")
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
                Spacer()
            }

            if let category = scope.category {
                Text(category.description)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                if viewModel.isCoverageBlocked(for: category) {
                    Label(
                        "This category could not be fully scanned — it needs "
                            + "administrator privileges.",
                        systemImage: "lock.fill"
                    )
                    .font(.callout)
                    .foregroundStyle(.secondary)
                }
            }
        }
        .padding()
    }

    // MARK: - Empty states

    /// An empty list has three quite different meanings, and a security tool must
    /// not conflate them. Previously all three rendered as a bare grid of empty
    /// placeholder rows with no text at all.
    @ViewBuilder
    private var emptyState: some View {
        if !viewModel.searchText.isEmpty {
            ContentUnavailableView.search(text: viewModel.searchText)
        } else if viewModel.hasActiveFilters, unfilteredCount > 0 {
            ContentUnavailableView {
                Label("No Matching Items", systemImage: "line.3.horizontal.decrease.circle")
            } description: {
                // One literal, so it stays a `LocalizedStringKey`. Joining two
                // literals with `+` produced a plain `String`, which skips Markdown
                // and printed the `^[…](inflect: true)` syntax verbatim.
                Text("^[\(unfilteredCount) item](inflect: true) found, but none match the active filters.")
            } actions: {
                Button("Clear Filters") { viewModel.clearFilters() }
                    .buttonStyle(.borderedProminent)
            }
        } else if let category = scope.category, viewModel.isCoverageBlocked(for: category) {
            ContentUnavailableView {
                Label("Coverage Incomplete", systemImage: "lock.fill")
            } description: {
                Text("This category needs administrator privileges, so it was not "
                     + "scanned. This is not the same as finding nothing.")
            } actions: {
                Button("How to Grant Access") { viewModel.openLoginItemsSettings() }
            }
        } else if viewModel.lastResult == nil {
            ContentUnavailableView {
                Label("No Scan Yet", systemImage: "magnifyingglass")
            } description: {
                Text("Run a scan to see what is configured to launch on this Mac.")
            } actions: {
                Button("Scan Now") { viewModel.startScanTask() }
                    .buttonStyle(.borderedProminent)
            }
        } else if let category = scope.category {
            ContentUnavailableView {
                Label("Nothing in \(category.displayName)", systemImage: category.sfSymbol)
            } description: {
                Text(category.whatIsNormal)
            }
        } else {
            ContentUnavailableView(
                "No Items",
                systemImage: "checkmark.circle",
                description: Text("Nothing matched.")
            )
        }
    }

    // MARK: - Table

    /// Two concrete tables rather than one with a conditional column.
    ///
    /// A `if` inside `TableColumnBuilder` makes the column list's generic type
    /// depend on a runtime condition, which the type checker cannot resolve in
    /// reasonable time. The shared behavior lives in `tableBehavior` so the two
    /// branches cannot drift.
    @ViewBuilder
    private func table(_ rows: [PersistenceItem]) -> some View {
        if scope.category == nil {
            Table(rows, selection: $selectedItemIDs, sortOrder: $sortOrder) {
                riskColumn
                categoryColumn
                nameColumn
                statusColumn
                signingColumn
                developerColumn
                pathColumn
            }
            .modifier(tableBehavior)
        } else {
            Table(rows, selection: $selectedItemIDs, sortOrder: $sortOrder) {
                riskColumn
                nameColumn
                statusColumn
                signingColumn
                developerColumn
                pathColumn
            }
            .modifier(tableBehavior)
        }
    }

    private var tableBehavior: TableBehavior {
        TableBehavior(
            menu: { ids in AnyView(contextMenu(for: ids)) },
            primaryAction: { ids in
                // Double-click focuses the inspector rather than opening a second,
                // differently-populated detail surface.
                selectedItem = filteredItems.first { ids.contains($0.id) }
            }
        )
    }

    private struct TableBehavior: ViewModifier {
        let menu: (Set<PersistenceItem.ID>) -> AnyView
        let primaryAction: (Set<PersistenceItem.ID>) -> Void

        func body(content: Content) -> some View {
            content
                .alternatingRowBackgrounds(.disabled)
                .contextMenu(forSelectionType: PersistenceItem.ID.self) { ids in
                    menu(ids)
                } primaryAction: { ids in
                    primaryAction(ids)
                }
        }
    }

    @ViewBuilder
    private func contextMenu(for ids: Set<PersistenceItem.ID>) -> some View {
        let items = filteredItems.filter { ids.contains($0.id) }
        if !items.isEmpty {
            let paths = items.compactMap { $0.configPath ?? $0.executablePath }

            if items.count == 1, let path = paths.first {
                Button("Reveal in Finder") {
                    NSWorkspace.shared.selectFile(path, inFileViewerRootedAtPath: "")
                }
            }
            if !paths.isEmpty {
                // Bulk actions: selecting several rows and copying their paths was
                // impossible, because the menu only ever acted on `ids.first`.
                Button(paths.count == 1 ? "Copy Path" : "Copy \(paths.count) Paths") {
                    copyToPasteboard(paths.joined(separator: "\n"))
                }
            }
            Button(items.count == 1 ? "Copy Details" : "Copy \(items.count) Items as Text") {
                copyToPasteboard(items.map(summary).joined(separator: "\n\n"))
            }
            if let hint = items.first?.category.investigationHint, items.count == 1 {
                Divider()
                Button("Copy Investigation Command") {
                    copyToPasteboard(hint)
                }
            }
        }
    }

    private func summary(_ item: PersistenceItem) -> String {
        var lines = [
            "\(item.name) — \(item.riskLevel.displayName)",
            "Category: \(item.category.displayName)",
        ]
        if let path = item.configPath { lines.append("Config: \(path)") }
        if let path = item.executablePath { lines.append("Executable: \(path)") }
        if !item.riskReasons.isEmpty {
            lines.append("Findings: \(item.riskReasons.joined(separator: "; "))")
        }
        return lines.joined(separator: "\n")
    }

    private func copyToPasteboard(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }



    // MARK: - Table Columns (broken out to help the type checker)

    private var riskColumn: some TableColumnContent<PersistenceItem, ItemComparator> {
        TableColumn("Risk", sortUsing: ItemComparator(.risk)) { (item: PersistenceItem) in
            RiskBadge(level: item.riskLevel, compact: true)
        }
        .width(min: 90, ideal: 110)
    }

    private var categoryColumn: some TableColumnContent<PersistenceItem, ItemComparator> {
        TableColumn("Category", sortUsing: ItemComparator(.category)) { (item: PersistenceItem) in
            Label(item.category.displayName, systemImage: item.category.sfSymbol)
                .font(.caption)
                .lineLimit(1)
        }
        .width(min: 110, ideal: 150)
    }

    private var nameColumn: some TableColumnContent<PersistenceItem, ItemComparator> {
        TableColumn("Name", sortUsing: ItemComparator(.name)) { (item: PersistenceItem) in
            VStack(alignment: .leading, spacing: 1) {
                Text(item.name)
                    .lineLimit(1)
                    // Reverse-DNS names carry their meaning at the end.
                    .truncationMode(.middle)
                    .help(item.name)
                if let label = item.label, label != item.name {
                    Text(label)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
        }
        .width(min: 150, ideal: 250)
    }

    private var statusColumn: some TableColumnContent<PersistenceItem, ItemComparator> {
        TableColumn("Status", sortUsing: ItemComparator(.status)) { (item: PersistenceItem) in
            Label {
                Text(item.isEnabled ? "Enabled" : "Disabled").font(.caption)
            } icon: {
                Image(systemName: item.isEnabled ? "play.circle.fill" : "pause.circle")
                    .foregroundStyle(item.isEnabled ? .primary : .secondary)
            }
            .accessibilityLabel(item.isEnabled ? "Enabled" : "Disabled")
        }
        .width(min: 80, ideal: 90)
    }

    private var signingColumn: some TableColumnContent<PersistenceItem, ItemComparator> {
        TableColumn("Signed", sortUsing: ItemComparator(.signing)) { (item: PersistenceItem) in
            SigningCellView(signingInfo: item.signingInfo)
        }
        .width(min: 90, ideal: 110)
    }

    private var developerColumn: some TableColumnContent<PersistenceItem, ItemComparator> {
        TableColumn("Developer", sortUsing: ItemComparator(.developer)) { (item: PersistenceItem) in
            Text(item.source.displayName)
                .font(.caption)
                .lineLimit(1)
                .truncationMode(.middle)
                .foregroundStyle(item.source.isApple ? .secondary : .primary)
        }
        .width(min: 80, ideal: 120)
    }

    private var pathColumn: some TableColumnContent<PersistenceItem, ItemComparator> {
        TableColumn("Path", sortUsing: ItemComparator(.path)) { (item: PersistenceItem) in
            let path = item.configPath ?? item.executablePath ?? "—"
            Text(path)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
                .help(path)
        }
        .width(min: 100, ideal: 200)
    }

    private var filteredItems: [PersistenceItem] {
        switch scope {
        case .everything: return viewModel.filteredItems
        case .category(let category): return viewModel.filteredItems(for: category)
        }
    }

    private var unfilteredCount: Int {
        switch scope {
        case .everything: return viewModel.lastResult?.items.count ?? 0
        case .category(let category): return viewModel.unfilteredCount(for: category)
        }
    }
}

// MARK: - Signing Cell

private struct SigningCellView: View {
    let signingInfo: SigningInfo?

    var body: some View {
        // Distinct glyphs per state, not just distinct tints — the previous version
        // separated "Signed" from "Notarized" purely by seal color.
        switch state {
        case .notarized:
            cell("Notarized", symbol: "checkmark.seal.fill", tint: .green)
        case .apple:
            cell("Apple", symbol: "apple.logo", tint: .secondary)
        case .signed:
            cell("Signed", symbol: "seal.fill", tint: .yellow)
        case .adHoc:
            cell("Ad-hoc", symbol: "questionmark.seal.fill", tint: .orange)
        case .unsigned:
            cell("Unsigned", symbol: "xmark.seal.fill", tint: .red)
        case .unverified:
            // Explicitly named, not a bare "--" that reads as missing data.
            cell("Not verified", symbol: "seal", tint: .secondary)
        }
    }

    private func cell(_ text: String, symbol: String, tint: Color) -> some View {
        Label {
            Text(text).font(.caption)
        } icon: {
            Image(systemName: symbol).foregroundStyle(tint)
        }
        .accessibilityLabel("Signature: \(text)")
        .help(helpText)
    }

    private enum State { case notarized, apple, signed, adHoc, unsigned, unverified }

    private var state: State {
        guard let info = signingInfo else { return .unverified }
        if !info.isSigned { return .unsigned }
        if info.isAppleSigned { return .apple }
        if info.isNotarized { return .notarized }
        if info.isAdHocSigned { return .adHoc }
        return .signed
    }

    private var helpText: String {
        switch state {
        case .notarized: return "Signed by an identified developer and notarized by Apple."
        case .apple: return "Signed by Apple as part of macOS."
        case .signed: return "Validly signed, but not notarized by Apple."
        case .adHoc: return "Has a signature, but no developer identity behind it."
        case .unsigned: return "No valid code signature."
        case .unverified:
            return "The signature could not be checked — this is not the same as unsigned."
        }
    }
}

// MARK: - Sort Keys

extension PersistenceItem {
    /// Sort key for risk level (uses sortOrder from RiskLevel).
    var riskSortKey: Int {
        riskLevel.sortOrder
    }

    var categorySortKey: String {
        category.displayName
    }

    /// Sort key for enabled/disabled status (enabled sorts above disabled).
    var statusSortKey: Int {
        isEnabled ? 1 : 0
    }

    /// Sort key for signing state: 0 = unverified, 1 = unsigned, 2 = ad-hoc,
    /// 3 = signed, 4 = notarized, 5 = Apple.
    var signingSortKey: Int {
        guard let info = signingInfo else { return 0 }
        if !info.isSigned { return 1 }
        if info.isAppleSigned { return 5 }
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


// MARK: - Sorting

/// A `Sendable` sort comparator for the items table.
///
/// `KeyPathComparator` would be the obvious choice, but `KeyPath` does not conform
/// to `Sendable` (swiftlang/swift#69487), so storing one in `@State` on a
/// `@MainActor` view warns today and fails to compile under the Swift 6 language
/// mode. Selecting the field with an enum keeps the comparator a plain value type.
struct ItemComparator: SortComparator, Hashable, Sendable {
    enum Field: Hashable, Sendable {
        case risk, category, name, status, signing, developer, path
    }

    var field: Field
    var order: SortOrder

    init(_ field: Field, order: SortOrder = .forward) {
        self.field = field
        self.order = order
    }

    func compare(_ lhs: PersistenceItem, _ rhs: PersistenceItem) -> ComparisonResult {
        let result: ComparisonResult
        switch field {
        case .risk:
            result = compareValues(lhs.riskSortKey, rhs.riskSortKey)
        case .status:
            result = compareValues(lhs.statusSortKey, rhs.statusSortKey)
        case .signing:
            result = compareValues(lhs.signingSortKey, rhs.signingSortKey)
        case .category:
            result = lhs.categorySortKey.localizedStandardCompare(rhs.categorySortKey)
        case .name:
            result = lhs.name.localizedStandardCompare(rhs.name)
        case .developer:
            result = lhs.developerSortKey.localizedStandardCompare(rhs.developerSortKey)
        case .path:
            result = lhs.pathSortKey.localizedStandardCompare(rhs.pathSortKey)
        }
        guard order == .reverse else { return result }
        switch result {
        case .orderedAscending: return .orderedDescending
        case .orderedDescending: return .orderedAscending
        case .orderedSame: return .orderedSame
        }
    }

    private func compareValues(_ lhs: Int, _ rhs: Int) -> ComparisonResult {
        if lhs == rhs { return .orderedSame }
        return lhs < rhs ? .orderedAscending : .orderedDescending
    }
}
