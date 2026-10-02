import SwiftUI
import Charts

/// Everything the dashboard draws, computed in one pass when the results or the
/// filters change. The dashboard used to derive each number on every render with
/// its own `items.filter`, roughly fifteen full passes over the inventory, and
/// re-rendered on every mouse movement over a card, chip or row.
struct DashboardStats {
    private(set) var total = 0
    private(set) var unsigned = 0
    private(set) var thirdParty = 0
    private(set) var riskCounts: [RiskLevel: Int] = [:]
    /// The ten categories with the most items, largest first.
    private(set) var topCategories: [(category: PersistenceCategory, count: Int)] = []
    /// High and critical items, worst first, capped at twenty.
    private(set) var attentionItems: [PersistenceItem] = []

    init() {}

    init(items: [PersistenceItem]) {
        total = items.count
        var categoryCounts: [PersistenceCategory: Int] = [:]
        var attention: [PersistenceItem] = []
        for item in items {
            riskCounts[item.riskLevel, default: 0] += 1
            categoryCounts[item.category, default: 0] += 1
            if item.signingInfo?.isSigned != true { unsigned += 1 }
            if !item.source.isApple { thirdParty += 1 }
            if item.riskLevel >= .high { attention.append(item) }
        }
        topCategories = categoryCounts
            .map { (category: $0.key, count: $0.value) }
            .sorted { lhs, rhs in
                if lhs.count != rhs.count { return lhs.count > rhs.count }
                return lhs.category.displayName < rhs.category.displayName
            }
            .prefix(10)
            .map { $0 }
        attentionItems = attention
            .sorted { $0.riskLevel != $1.riskLevel ? $0.riskLevel > $1.riskLevel : $0.name < $1.name }
            .prefix(20)
            .map { $0 }
    }

    func count(_ level: RiskLevel) -> Int { riskCounts[level] ?? 0 }

    /// (level, count) pairs for the risk donut, without zero-count levels.
    var riskSlices: [(level: RiskLevel, count: Int)] {
        RiskLevel.allCases.compactMap { level in
            let count = count(level)
            return count > 0 ? (level, count) : nil
        }
    }
}

struct DashboardView: View {
    @EnvironmentObject var viewModel: ScanViewModel
    @Binding var selection: SidebarSelection?
    @Binding var selectedItem: PersistenceItem?

    @State private var popoverItem: PersistenceItem?

    private var stats: DashboardStats { viewModel.dashboardStats }

    var body: some View {
        if viewModel.lastResult == nil {
            if viewModel.isScanning {
                // The progress strip above says how far along the scan is. A
                // dashboard of zeros here read as "your Mac has nothing on it".
                ContentUnavailableView(
                    "Scanning…",
                    systemImage: "magnifyingglass",
                    description: Text("Results will appear here when the scan finishes.")
                )
            } else {
                // Before the first scan there is nothing to summarize.
                ContentUnavailableView {
                    Label("No Scan Yet", systemImage: "shield.lefthalf.filled")
                } description: {
                    Text("LaunchAudit inspects every place macOS can be told to run "
                         + "something automatically — at boot, at login, on a schedule, "
                         + "or in response to an event.")
                } actions: {
                    Button("Run a Scan") { viewModel.startScanTask() }
                        .buttonStyle(.borderedProminent)
                }
            }
        } else {
            dashboardContent
        }
    }

    private var dashboardContent: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Privilege banner — shown inside the scroll content rather
                // than above the ScrollView. Putting it above (as a sibling
                // or via safeAreaInset) caused the ScrollView's content to
                // be hidden behind it: contentOffset 0 was the natural top
                // of the content, but that top was now occluded, so the
                // user couldn't scroll further up to reveal it.
                if viewModel.shouldShowPrivilegeBanner {
                    PrivilegeBanner()
                }

                // Header
                if let result = viewModel.lastResult {
                    HStack {
                        Text("Audit Summary")
                            .font(.title2.bold())
                        if viewModel.hideAppleSigned {
                            Text("(System items hidden)")
                                .font(.callout)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text("Last scan: \(result.scanDate.formatted())")
                            .foregroundStyle(.secondary)
                        Text("(\(String(format: "%.1fs", result.scanDuration)))")
                            .foregroundStyle(.tertiary)
                    }
                }

                // Summary Cards
                summaryCards

                HStack(alignment: .top, spacing: 20) {
                    RiskDistributionView(stats: stats, onSelect: filterByRisk)
                    CategoryBreakdownView(data: stats.topCategories, onSelect: navigateToCategory)
                }

                attentionNeededSection

                scanCoverageSection
            }
            .padding()
        }
        .background(.background)
    }

    // MARK: - Summary Cards

    private var summaryCards: some View {
        LazyVGrid(columns: Array(repeating: GridItem(.flexible()), count: 5), spacing: 12) {
            InteractiveSummaryCard(
                title: "Total Items", value: stats.total,
                icon: "list.bullet", color: .blue,
                help: "View all items", action: navigateClearing
            )
            InteractiveSummaryCard(
                title: "Critical", value: stats.count(.critical),
                icon: "exclamationmark.triangle.fill", color: .red,
                help: "Filter to critical risk items", action: { filterByRisk(.critical) }
            )
            InteractiveSummaryCard(
                title: "High", value: stats.count(.high),
                icon: "exclamationmark.circle.fill", color: .orange,
                help: "Filter to high risk items", action: { filterByRisk(.high) }
            )
            InteractiveSummaryCard(
                title: "Unsigned", value: stats.unsigned,
                icon: "signature", color: .purple,
                help: "Filter to unsigned items", action: filterUnsigned
            )
            InteractiveSummaryCard(
                title: "Third-Party", value: stats.thirdParty,
                icon: "person.2", color: .teal,
                help: "Filter to third-party items", action: filterThirdParty
            )
        }
    }

    // MARK: - Attention Needed

    @ViewBuilder
    private var attentionNeededSection: some View {
        if !stats.attentionItems.isEmpty {
            GroupBox("Attention Needed") {
                LazyVStack(spacing: 0) {
                    ForEach(stats.attentionItems) { item in
                        AttentionRow(
                            item: item,
                            onOpen: { navigateToItem(item) },
                            onShowDetails: { popoverItem = item },
                            onGoToCategory: { navigateToCategory(item.category) }
                        )
                    }
                }
            }
            .itemDetailOverlay(item: $popoverItem)
        }
    }

    // MARK: - Scan Warnings

    /// Scan coverage.
    ///
    /// This is the panel that tells the user which results are incomplete. It never
    /// appeared before, because no scanner ever reported an error — so "0 items"
    /// was indistinguishable from "could not look".
    @ViewBuilder
    private var scanCoverageSection: some View {
        if let result = viewModel.lastResult, result.hasCoverageGaps {
            GroupBox {
                VStack(alignment: .leading, spacing: 8) {
                    Label {
                        Text("Scan Coverage")
                            .font(.headline)
                    } icon: {
                        Image(systemName: "exclamationmark.shield")
                    }

                    if !result.ranAsRoot {
                        coverageRow(
                            symbol: "lock.fill",
                            title: "Not run with administrator privileges",
                            detail: "Categories that need root were skipped. "
                                + "Run `sudo launchaudit scan` for full coverage."
                        )
                    }

                    if !result.hadAuthoritativeLaunchdState {
                        coverageRow(
                            symbol: "questionmark.circle",
                            title: "launchd enable/disable state is unverified",
                            detail: "The override database needs root to read, so "
                                + "Enabled/Disabled comes from each plist and can be wrong."
                        )
                    }

                    ForEach(result.errors) { error in
                        CoverageErrorRow(error: error) {
                            if let category = error.category { navigateToCategory(category) }
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(4)
            }
        }
    }

    private func coverageRow(symbol: String, title: String, detail: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: symbol)
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).fontWeight(.medium)
                Text(detail)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .accessibilityElement(children: .combine)
    }

    // MARK: - Navigation Actions

    private func navigateToCategory(_ category: PersistenceCategory) {
        selection = .category(category)
    }

    private func navigateToItem(_ item: PersistenceItem) {
        // Set both in one update. The previous version navigated and then set the
        // selection 0.1s later via `asyncAfter`, which raced a slow first render.
        selection = .category(item.category)
        selectedItem = item
    }

    /// Clear every filter and show the whole inventory.
    ///
    /// The summary cards used to only mutate a filter that the dashboard itself did
    /// not apply, so clicking "Critical — 2" changed a toolbar picker and nothing
    /// else on screen. They now navigate to the matching list.
    private func navigateClearing() {
        viewModel.minimumRiskFilter = nil
        viewModel.showOnlyUnsigned = false
        viewModel.showOnlyThirdParty = false
        viewModel.searchText = ""
        selection = .allItems
    }

    private func filterByRisk(_ level: RiskLevel) {
        viewModel.minimumRiskFilter = level
        viewModel.showOnlyUnsigned = false
        viewModel.showOnlyThirdParty = false
        viewModel.searchText = ""
        selection = .allItems
    }

    private func filterUnsigned() {
        viewModel.searchText = ""
        viewModel.minimumRiskFilter = nil
        viewModel.showOnlyThirdParty = false
        viewModel.showOnlyUnsigned.toggle()
        if viewModel.showOnlyUnsigned { selection = .allItems }
    }

    private func filterThirdParty() {
        defer { if viewModel.showOnlyThirdParty { selection = .allItems } }
        viewModel.searchText = ""
        viewModel.minimumRiskFilter = nil
        viewModel.showOnlyUnsigned = false
        viewModel.showOnlyThirdParty.toggle()
    }
}

// MARK: - Risk Distribution

/// The risk donut and its legend. Hover state lives here, so moving the mouse over
/// the chart redraws the chart rather than the whole dashboard.
private struct RiskDistributionView: View {
    let stats: DashboardStats
    let onSelect: (RiskLevel) -> Void

    @State private var hoveredRiskLevel: RiskLevel?
    @State private var selectedAngleValue: Double?

    var body: some View {
        GroupBox("Risk Distribution") {
            if stats.total > 0 {
                donutChart
                    .frame(height: 200)

                // Hover tooltip under the chart
                if let hovered = hoveredRiskLevel {
                    let count = stats.count(hovered)
                    HStack(spacing: 6) {
                        Circle().fill(hovered.color).frame(width: 10, height: 10)
                        Text("\(hovered.displayName): \(count) item\(count == 1 ? "" : "s")")
                            .font(.callout.weight(.medium))
                        Text("— click to filter")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 4)
                    .transition(.opacity)
                }

                legend
            }
        }
        .frame(maxWidth: .infinity)
    }

    private var donutChart: some View {
        let slices = stats.riskSlices
        return Chart {
            ForEach(slices, id: \.level) { slice in
                SectorMark(
                    angle: .value("Count", slice.count),
                    innerRadius: .ratio(hoveredRiskLevel == slice.level ? 0.45 : 0.5),
                    outerRadius: .ratio(hoveredRiskLevel == slice.level ? 1.0 : 0.92),
                    angularInset: hoveredRiskLevel == slice.level ? 2.0 : 0.5
                )
                .foregroundStyle(slice.level.color)
                .opacity(hoveredRiskLevel == nil || hoveredRiskLevel == slice.level ? 1.0 : 0.35)
                .annotation(position: .overlay) {
                    Text("\(slice.count)")
                        .font(hoveredRiskLevel == slice.level ? .caption.bold() : .caption2.bold())
                        .foregroundStyle(.white)
                }
            }
        }
        .chartAngleSelection(value: $selectedAngleValue)
        .chartOverlay { _ in
            GeometryReader { geo in
                Rectangle()
                    .fill(Color.clear)
                    .contentShape(Rectangle())
                    .onContinuousHover { phase in
                        let level: RiskLevel?
                        switch phase {
                        case .active(let loc):
                            level = resolveHoveredSector(at: loc, in: geo.size, slices: slices)
                        case .ended:
                            level = nil
                        }
                        // Continuous hover fires on every mouse movement; only an
                        // actual change of sector should cause a redraw.
                        if level != hoveredRiskLevel { hoveredRiskLevel = level }
                    }
                    .onTapGesture { loc in
                        if let level = resolveHoveredSector(at: loc, in: geo.size, slices: slices) {
                            onSelect(level)
                        }
                    }
            }
        }
        .animation(.easeInOut(duration: 0.15), value: hoveredRiskLevel)
        .onChange(of: selectedAngleValue) { _, newValue in
            if let angle = newValue, let level = Self.riskLevel(forAngle: angle, slices: slices) {
                onSelect(level)
                selectedAngleValue = nil
            }
        }
    }

    /// Given a cumulative angle value from the chart, resolve which risk level it falls in.
    private static func riskLevel(
        forAngle angle: Double,
        slices: [(level: RiskLevel, count: Int)]
    ) -> RiskLevel? {
        var cumulative = 0.0
        for slice in slices {
            cumulative += Double(slice.count)
            if angle <= cumulative { return slice.level }
        }
        return slices.last?.level
    }

    /// Convert a point inside the chart frame to the risk level whose sector it falls in.
    private func resolveHoveredSector(
        at location: CGPoint,
        in size: CGSize,
        slices: [(level: RiskLevel, count: Int)]
    ) -> RiskLevel? {
        let center = CGPoint(x: size.width / 2, y: size.height / 2)
        let dx = location.x - center.x
        let dy = location.y - center.y
        let distance = sqrt(dx * dx + dy * dy)
        let outerRadius = min(size.width, size.height) / 2
        let innerRadius = outerRadius * 0.5

        // Outside the donut ring
        guard distance >= innerRadius * 0.8, distance <= outerRadius * 1.05 else { return nil }

        // atan2 gives angle from positive-x axis; chart starts from top (negative-y)
        var angle = atan2(dx, -dy) // radians from 12-o'clock, clockwise
        if angle < 0 { angle += 2 * .pi }

        let totalCount = slices.reduce(0) { $0 + $1.count }
        guard totalCount > 0 else { return nil }

        let fraction = angle / (2 * .pi)
        return Self.riskLevel(forAngle: fraction * Double(totalCount), slices: slices)
    }

    private var legend: some View {
        HStack(spacing: 12) {
            ForEach(RiskLevel.allCases, id: \.self) { level in
                Button {
                    onSelect(level)
                } label: {
                    HStack(spacing: 4) {
                        Circle().fill(level.color).frame(width: 8, height: 8)
                        Text("\(level.displayName) (\(stats.count(level)))")
                            .font(.caption)
                    }
                    .padding(.horizontal, 6)
                    .padding(.vertical, 3)
                    .background(
                        hoveredRiskLevel == level ? level.color.opacity(0.15) : Color.clear,
                        in: RoundedRectangle(cornerRadius: 4)
                    )
                }
                .buttonStyle(.plain)
                .onHover { inside in
                    if inside { hoveredRiskLevel = level } else if hoveredRiskLevel == level { hoveredRiskLevel = nil }
                }
                .help("Filter to \(level.displayName.lowercased()) risk items")
            }
        }
    }
}

// MARK: - Category Breakdown

private struct CategoryBreakdownView: View {
    let data: [(category: PersistenceCategory, count: Int)]
    let onSelect: (PersistenceCategory) -> Void

    @State private var hoveredCategory: PersistenceCategory?

    var body: some View {
        GroupBox("Items by Category (Top 10)") {
            if !data.isEmpty {
                Chart(data, id: \.category) { item in
                    BarMark(
                        x: .value("Count", item.count),
                        y: .value("Category", item.category.displayName)
                    )
                    .foregroundStyle(
                        hoveredCategory == item.category ? Color.blue : Color.blue.opacity(0.7)
                    )
                }
                .frame(height: 250)

                FlowLayout(spacing: 6) {
                    ForEach(data, id: \.category) { item in
                        chip(item.category)
                    }
                }
                .padding(.top, 4)
            }
        }
        .frame(maxWidth: .infinity)
    }

    private func chip(_ category: PersistenceCategory) -> some View {
        Button {
            onSelect(category)
        } label: {
            HStack(spacing: 4) {
                Image(systemName: category.sfSymbol)
                    .font(.caption2)
                Text(category.displayName)
                    .font(.caption)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(
                hoveredCategory == category ? Color.blue.opacity(0.15) : Color.clear,
                in: RoundedRectangle(cornerRadius: 6)
            )
        }
        .buttonStyle(.plain)
        .onHover { inside in
            if inside { hoveredCategory = category } else if hoveredCategory == category { hoveredCategory = nil }
        }
        .help("View \(category.displayName)")
    }
}

// MARK: - Attention Row

private struct AttentionRow: View {
    let item: PersistenceItem
    let onOpen: () -> Void
    let onShowDetails: () -> Void
    let onGoToCategory: () -> Void

    @State private var isHovered = false

    var body: some View {
        HStack {
            RiskBadge(level: item.riskLevel)
            Text(item.name)
                .lineLimit(1)
            Spacer()
            Text(item.category.displayName)
                .font(.caption)
                .foregroundStyle(.secondary)
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(isHovered ? Color.blue.opacity(0.1) : Color.clear, in: Capsule())
            if let reason = item.riskReasons.first {
                Text(reason)
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .lineLimit(1)
            }
            Image(systemName: "chevron.right")
                .font(.caption2)
                .foregroundStyle(.tertiary)
        }
        .padding(.vertical, 4)
        .padding(.horizontal, 6)
        .background(
            isHovered ? Color.primary.opacity(0.04) : Color.clear,
            in: RoundedRectangle(cornerRadius: 6)
        )
        .contentShape(Rectangle())
        .onHover { isHovered = $0 }
        .onTapGesture(perform: onOpen)
        .contextMenu {
            Button("View Details", action: onShowDetails)
            Button("Go to \(item.category.displayName)", action: onGoToCategory)
            if let path = item.configPath ?? item.executablePath {
                Divider()
                Button("Reveal in Finder") {
                    NSWorkspace.shared.selectFile(path, inFileViewerRootedAtPath: "")
                }
                Button("Copy Path") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(path, forType: .string)
                }
            }
        }
    }
}

// MARK: - Coverage Error Row

private struct CoverageErrorRow: View {
    let error: ScanError
    let action: () -> Void

    @State private var isHovered = false

    var body: some View {
        // A real Button, so it is keyboard-reachable and announced as a control.
        // These used to be `.onTapGesture` on a plain HStack.
        Button(action: action) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Image(systemName: error.isPermissionDenied
                      ? "lock.fill" : "exclamationmark.triangle")
                    .foregroundStyle(.secondary)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(error.category?.displayName ?? "Scan")
                        .fontWeight(.medium)
                    Text(error.message)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
                if error.category != nil {
                    Image(systemName: "chevron.right")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                        .accessibilityHidden(true)
                }
            }
            .padding(.vertical, 4)
            .padding(.horizontal, 6)
            .background(
                isHovered ? AnyShapeStyle(.selection) : AnyShapeStyle(.clear),
                in: RoundedRectangle(cornerRadius: 6)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(error.category == nil)
        .onHover { isHovered = $0 }
        .accessibilityLabel(
            "\(error.category?.displayName ?? "Scan") coverage issue: \(error.message)"
        )
        .help(error.category.map { "Go to \($0.displayName)" } ?? error.message)
    }
}

// MARK: - Interactive Summary Card

struct InteractiveSummaryCard: View {
    let title: String
    let value: Int
    let icon: String
    let color: Color
    let help: String
    let action: () -> Void

    @State private var isHovered = false

    var body: some View {
        GroupBox {
            VStack(spacing: 8) {
                Image(systemName: icon)
                    .font(.title2)
                    .foregroundStyle(color)
                Text("\(value)")
                    .font(.title.bold())
                    .monospacedDigit()
                Text(title)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 8)
        }
        // A stroke rather than a scale-and-shadow effect: the old hover state
        // rescaled and re-shadowed the whole card on every enter and exit, which
        // forced an offscreen render pass per card.
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(isHovered ? color.opacity(0.5) : .clear, lineWidth: 2)
        )
        .contentShape(Rectangle())
        .onHover { isHovered = $0 }
        .onTapGesture(perform: action)
        .help(help)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isButton)
        .accessibilityAction(.default, action)
    }
}

// `RiskBadge` and `RiskIndicator` live in RiskLevel+Presentation.swift, which
// owns the contrast-checked palette and the per-level glyphs.

// MARK: - Flow Layout for category chips

struct FlowLayout: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let result = arrangeSubviews(proposal: proposal, subviews: subviews)
        return result.size
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let result = arrangeSubviews(proposal: proposal, subviews: subviews)
        for (index, position) in result.positions.enumerated() {
            subviews[index].place(
                at: CGPoint(x: bounds.minX + position.x, y: bounds.minY + position.y),
                proposal: .unspecified
            )
        }
    }

    private func arrangeSubviews(proposal: ProposedViewSize, subviews: Subviews) -> (positions: [CGPoint], size: CGSize) {
        let maxWidth = proposal.width ?? .infinity
        var positions: [CGPoint] = []
        var x: CGFloat = 0
        var y: CGFloat = 0
        var rowHeight: CGFloat = 0
        var maxX: CGFloat = 0

        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if x + size.width > maxWidth, x > 0 {
                x = 0
                y += rowHeight + spacing
                rowHeight = 0
            }
            positions.append(CGPoint(x: x, y: y))
            rowHeight = max(rowHeight, size.height)
            x += size.width + spacing
            maxX = max(maxX, x)
        }

        return (positions, CGSize(width: maxX, height: y + rowHeight))
    }
}
