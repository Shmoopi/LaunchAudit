import SwiftUI
import Charts

struct DashboardView: View {
    @EnvironmentObject var viewModel: ScanViewModel
    @Binding var selectedCategory: PersistenceCategory?
    @Binding var showDashboard: Bool
    @Binding var selectedItem: PersistenceItem?

    @State private var popoverItem: PersistenceItem?
    @State private var hoveredCard: String?
    @State private var hoveredRiskLevel: RiskLevel?
    @State private var hoveredCategoryBar: PersistenceCategory?
    @State private var hoveredAttentionItem: PersistenceItem.ID?
    @State private var hoveredWarning: ScanError.ID?
    @State private var selectedAngleValue: Double?

    private var items: [PersistenceItem] { viewModel.displayItems }

    /// Pre-computed (level, count) pairs for the risk donut, filtering out zero-count levels.
    private var riskSlices: [(level: RiskLevel, count: Int)] {
        RiskLevel.allCases.compactMap { level in
            let count = items.filter { $0.riskLevel == level }.count
            return count > 0 ? (level, count) : nil
        }
    }

    /// Given a cumulative angle value from the chart, resolve which risk level it falls in.
    private func riskLevel(forAngle angle: Double) -> RiskLevel? {
        var cumulative = 0.0
        for slice in riskSlices {
            cumulative += Double(slice.count)
            if angle <= cumulative { return slice.level }
        }
        return riskSlices.last?.level
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
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
                    riskDistributionChart
                    categoryBarChart
                }

                attentionNeededSection

                scanWarningsSection
            }
            .padding()
        }
        .background(.background)
    }

    // MARK: - Summary Cards

    private var summaryCards: some View {
        LazyVGrid(columns: Array(repeating: GridItem(.flexible()), count: 5), spacing: 12) {
            InteractiveSummaryCard(
                title: "Total Items",
                value: "\(items.count)",
                icon: "list.bullet",
                color: .blue,
                isHovered: hoveredCard == "total"
            )
            .onHover { hoveredCard = $0 ? "total" : nil }
            .onTapGesture { navigateClearing() }
            .help("View all items")

            InteractiveSummaryCard(
                title: "Critical",
                value: "\(items.filter { $0.riskLevel == .critical }.count)",
                icon: "exclamationmark.triangle.fill",
                color: .red,
                isHovered: hoveredCard == "critical"
            )
            .onHover { hoveredCard = $0 ? "critical" : nil }
            .onTapGesture { filterByRisk(.critical) }
            .help("Filter to critical risk items")

            InteractiveSummaryCard(
                title: "High",
                value: "\(items.filter { $0.riskLevel == .high }.count)",
                icon: "exclamationmark.circle.fill",
                color: .orange,
                isHovered: hoveredCard == "high"
            )
            .onHover { hoveredCard = $0 ? "high" : nil }
            .onTapGesture { filterByRisk(.high) }
            .help("Filter to high risk items")

            InteractiveSummaryCard(
                title: "Unsigned",
                value: "\(items.filter { $0.signingInfo?.isSigned != true }.count)",
                icon: "signature",
                color: .purple,
                isHovered: hoveredCard == "unsigned"
            )
            .onHover { hoveredCard = $0 ? "unsigned" : nil }
            .onTapGesture { filterUnsigned() }
            .help("Filter to unsigned items")

            InteractiveSummaryCard(
                title: "Third-Party",
                value: "\(items.filter { !$0.source.isApple }.count)",
                icon: "person.2",
                color: .teal,
                isHovered: hoveredCard == "thirdparty"
            )
            .onHover { hoveredCard = $0 ? "thirdparty" : nil }
            .onTapGesture { filterThirdParty() }
            .help("Filter to third-party items")
        }
    }

    // MARK: - Risk Distribution Chart

    private var riskDistributionChart: some View {
        GroupBox("Risk Distribution") {
            if !items.isEmpty {
                riskDonutChart
                    .frame(height: 200)

                // Hover tooltip under the chart
                if let hovered = hoveredRiskLevel {
                    let count = items.filter { $0.riskLevel == hovered }.count
                    HStack(spacing: 6) {
                        Circle().fill(hovered.color).frame(width: 10, height: 10)
                        Text("\(hovered.displayName): \(count) item\(count == 1 ? "" : "s")")
                            .font(.callout.weight(.medium))
                        Text("— click to filter")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 4)
                    .transition(.opacity.combined(with: .scale(scale: 0.95)))
                    .animation(.easeInOut(duration: 0.15), value: hoveredRiskLevel)
                }

                riskLegend
            }
        }
        .frame(maxWidth: .infinity)
    }

    private var riskDonutChart: some View {
        Chart {
            ForEach(riskSlices, id: \.level) { slice in
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
                        switch phase {
                        case .active(let loc):
                            hoveredRiskLevel = resolveHoveredSector(at: loc, in: geo.size)
                        case .ended:
                            hoveredRiskLevel = nil
                        }
                    }
                    .onTapGesture { loc in
                        if let level = resolveHoveredSector(at: loc, in: geo.size) {
                            filterByRisk(level)
                        }
                    }
            }
        }
        .animation(.easeInOut(duration: 0.15), value: hoveredRiskLevel)
        .onChange(of: selectedAngleValue) { _, newValue in
            if let angle = newValue, let level = riskLevel(forAngle: angle) {
                filterByRisk(level)
                selectedAngleValue = nil
            }
        }
    }

    /// Convert a point inside the chart frame to the risk level whose sector it falls in.
    private func resolveHoveredSector(at location: CGPoint, in size: CGSize) -> RiskLevel? {
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

        let totalCount = riskSlices.reduce(0) { $0 + $1.count }
        guard totalCount > 0 else { return nil }

        let fraction = angle / (2 * .pi)
        let targetValue = fraction * Double(totalCount)

        return riskLevel(forAngle: targetValue)
    }

    private var riskLegend: some View {
        HStack(spacing: 12) {
            ForEach(RiskLevel.allCases, id: \.self) { level in
                riskLegendButton(level: level)
            }
        }
    }

    private func riskLegendButton(level: RiskLevel) -> some View {
        let count = items.filter { $0.riskLevel == level }.count
        return Button {
            filterByRisk(level)
        } label: {
            HStack(spacing: 4) {
                Circle().fill(level.color).frame(width: 8, height: 8)
                Text("\(level.displayName) (\(count))")
                    .font(.caption)
            }
            .padding(.horizontal, 6)
            .padding(.vertical, 3)
            .background(
                hoveredRiskLevel == level
                    ? level.color.opacity(0.15)
                    : Color.clear,
                in: RoundedRectangle(cornerRadius: 4)
            )
        }
        .buttonStyle(.plain)
        .onHover { hoveredRiskLevel = $0 ? level : nil }
        .help("Filter to \(level.displayName.lowercased()) risk items")
    }

    // MARK: - Category Bar Chart

    private var categoryBarChart: some View {
        let grouped = Dictionary(grouping: items, by: \.category)
        let mapped = grouped.map { (category: $0.key, count: $0.value.count) }
        let categoryCounts = mapped
            .sorted { lhs, rhs in
                if lhs.count != rhs.count { return lhs.count > rhs.count }
                return lhs.category.displayName < rhs.category.displayName
            }
            .prefix(10)

        return GroupBox("Items by Category (Top 10)") {
            if !items.isEmpty {
                categoryChart(data: Array(categoryCounts))
                    .frame(height: 250)

                categoryChips(data: Array(categoryCounts))
                    .padding(.top, 4)
            }
        }
        .frame(maxWidth: .infinity)
    }

    private func categoryChart(data: [(category: PersistenceCategory, count: Int)]) -> some View {
        Chart(data, id: \.category) { item in
            BarMark(
                x: .value("Count", item.count),
                y: .value("Category", item.category.displayName)
            )
            .foregroundStyle(
                hoveredCategoryBar == item.category
                    ? Color.blue
                    : Color.blue.opacity(0.7)
            )
        }
    }

    private func categoryChips(data: [(category: PersistenceCategory, count: Int)]) -> some View {
        FlowLayout(spacing: 6) {
            ForEach(data, id: \.category) { item in
                categoryChipButton(category: item.category)
            }
        }
    }

    private func categoryChipButton(category: PersistenceCategory) -> some View {
        Button {
            navigateToCategory(category)
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
                hoveredCategoryBar == category
                    ? Color.blue.opacity(0.15)
                    : Color.clear,
                in: RoundedRectangle(cornerRadius: 6)
            )
        }
        .buttonStyle(.plain)
        .onHover { hoveredCategoryBar = $0 ? category : nil }
        .help("View \(category.displayName)")
    }

    // MARK: - Attention Needed

    private var attentionNeededSection: some View {
        let attentionItems = items
            .filter { $0.riskLevel >= .high }
            .sorted { $0.riskLevel != $1.riskLevel ? $0.riskLevel > $1.riskLevel : $0.name < $1.name }

        return Group {
            if !attentionItems.isEmpty {
                GroupBox("Attention Needed") {
                    ForEach(attentionItems.prefix(20)) { item in
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
                                .background(
                                    hoveredAttentionItem == item.id
                                        ? Color.blue.opacity(0.1)
                                        : Color.clear,
                                    in: Capsule()
                                )
                            if !item.riskReasons.isEmpty {
                                Text(item.riskReasons.first!)
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
                            hoveredAttentionItem == item.id
                                ? Color.primary.opacity(0.04)
                                : Color.clear,
                            in: RoundedRectangle(cornerRadius: 6)
                        )
                        .contentShape(Rectangle())
                        .onHover { hoveredAttentionItem = $0 ? item.id : nil }
                        .onTapGesture {
                            navigateToItem(item)
                        }
                        .contextMenu {
                            Button("View Details") {
                                popoverItem = item
                            }
                            Button("Go to \(item.category.displayName)") {
                                navigateToCategory(item.category)
                            }
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
                .itemDetailOverlay(item: $popoverItem)
            }
        }
    }

    // MARK: - Scan Warnings

    private var scanWarningsSection: some View {
        Group {
            if let result = viewModel.lastResult, !result.errors.isEmpty {
                GroupBox("Scan Warnings") {
                    ForEach(result.errors) { error in
                        HStack {
                            Image(systemName: error.isPermissionDenied ? "lock.fill" : "exclamationmark.triangle")
                                .foregroundStyle(.orange)
                            Text(error.category.displayName)
                                .fontWeight(.medium)
                            Text(error.message)
                                .foregroundStyle(.secondary)
                            Spacer()
                            Image(systemName: "chevron.right")
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                        }
                        .padding(.vertical, 4)
                        .padding(.horizontal, 6)
                        .background(
                            hoveredWarning == error.id
                                ? Color.primary.opacity(0.04)
                                : Color.clear,
                            in: RoundedRectangle(cornerRadius: 6)
                        )
                        .contentShape(Rectangle())
                        .onHover { hoveredWarning = $0 ? error.id : nil }
                        .onTapGesture {
                            navigateToCategory(error.category)
                        }
                        .help("Go to \(error.category.displayName)")
                    }
                }
            }
        }
    }

    // MARK: - Navigation Actions

    private func navigateToCategory(_ category: PersistenceCategory) {
        selectedCategory = category
        showDashboard = false
    }

    private func navigateToItem(_ item: PersistenceItem) {
        selectedCategory = item.category
        showDashboard = false
        // Slight delay so the list view has time to appear
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
            selectedItem = item
        }
    }

    private func navigateClearing() {
        viewModel.minimumRiskFilter = nil
        viewModel.showOnlyUnsigned = false
        viewModel.showOnlyThirdParty = false
        viewModel.searchText = ""
    }

    private func filterByRisk(_ level: RiskLevel) {
        viewModel.minimumRiskFilter = level
        viewModel.showOnlyUnsigned = false
        viewModel.showOnlyThirdParty = false
        viewModel.searchText = ""
    }

    private func filterUnsigned() {
        viewModel.searchText = ""
        viewModel.minimumRiskFilter = nil
        viewModel.showOnlyThirdParty = false
        viewModel.showOnlyUnsigned.toggle()
    }

    private func filterThirdParty() {
        viewModel.searchText = ""
        viewModel.minimumRiskFilter = nil
        viewModel.showOnlyUnsigned = false
        viewModel.showOnlyThirdParty.toggle()
    }
}

// MARK: - Interactive Summary Card

struct InteractiveSummaryCard: View {
    let title: String
    let value: String
    let icon: String
    let color: Color
    let isHovered: Bool

    var body: some View {
        GroupBox {
            VStack(spacing: 8) {
                Image(systemName: icon)
                    .font(.title2)
                    .foregroundStyle(color)
                Text(value)
                    .font(.title.bold())
                Text(title)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 8)
        }
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(isHovered ? color.opacity(0.5) : .clear, lineWidth: 2)
        )
        .scaleEffect(isHovered ? 1.03 : 1.0)
        .shadow(color: isHovered ? color.opacity(0.2) : .clear, radius: 4)
        .animation(.easeInOut(duration: 0.15), value: isHovered)
        .contentShape(Rectangle())
    }
}

// MARK: - Risk Badge (unchanged)

struct RiskBadge: View {
    let level: RiskLevel

    var body: some View {
        Text(level.displayName)
            .font(.caption2.bold())
            .foregroundStyle(.white)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(level.color, in: Capsule())
    }
}

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
