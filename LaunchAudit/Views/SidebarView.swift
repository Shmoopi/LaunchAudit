import SwiftUI

/// What the sidebar can have selected.
///
/// Dashboard used to be a `Button` inside a `List(selection:)` that only tracked
/// `PersistenceCategory?`, so it could never show the standard selection
/// highlight — the window used two different selection languages at once. Modeling
/// both cases in one enum lets the `List` do its own job.
enum SidebarSelection: Hashable {
    case dashboard
    /// Every item, across all categories.
    ///
    /// Without this there was no way to see the whole inventory or to search it:
    /// the only lists were per-category, so finding `com.evil.updater` meant first
    /// guessing which of 36 categories it lived in.
    case allItems
    case category(PersistenceCategory)
}

struct SidebarView: View {
    @EnvironmentObject var viewModel: ScanViewModel
    @Binding var selection: SidebarSelection?

    var body: some View {
        List(selection: $selection) {
            Label("Dashboard", systemImage: "gauge.with.dots.needle.33percent")
                .tag(SidebarSelection.dashboard)

            Label("All Items", systemImage: "list.bullet.rectangle")
                .badge(viewModel.filteredItems.count)
                .tag(SidebarSelection.allItems)
                .accessibilityLabel("All items, \(viewModel.filteredItems.count) items")

            ForEach(CategoryGroup.allCases) { group in
                let categories = visibleCategories(in: group)
                // Hide a whole section when nothing in it survives the filter.
                if !categories.isEmpty {
                    Section(group.rawValue) {
                        ForEach(categories) { category in
                            categoryRow(category)
                                .tag(SidebarSelection.category(category))
                        }
                    }
                }
            }
        }
        .listStyle(.sidebar)
        .safeAreaInset(edge: .bottom) {
            if hasHiddenCategories {
                hiddenCategoriesFooter
            }
        }
    }

    /// Categories to show in a group.
    ///
    /// `hideEmptyCategories` was declared on the view model and never read
    /// anywhere, which is why two-thirds of the sidebar was rows reading `0` and
    /// the categories that actually found something were buried among them.
    private func visibleCategories(in group: CategoryGroup) -> [PersistenceCategory] {
        guard viewModel.hideEmptyCategories, viewModel.lastResult != nil else {
            return group.categories
        }
        return group.categories.filter { category in
            viewModel.itemCount(for: category) > 0
                // Never hide a category the user is currently looking at.
                || selection == .category(category)
        }
    }

    private var hasHiddenCategories: Bool {
        guard viewModel.hideEmptyCategories, viewModel.lastResult != nil else { return false }
        return CategoryGroup.allCases.contains { group in
            visibleCategories(in: group).count < group.categories.count
        }
    }

    private var hiddenCategoriesFooter: some View {
        let total = PersistenceCategory.allCases.count
        let shown = CategoryGroup.allCases.reduce(0) { $0 + visibleCategories(in: $1).count }
        return Button {
            viewModel.hideEmptyCategories = false
        } label: {
            Label(
                "^[\(total - shown) empty category](inflect: true) hidden",
                systemImage: "eye.slash"
            )
            .font(.caption)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .buttonStyle(.plain)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(.bar)
        .help("Show every category, including those with no results")
    }

    private func categoryRow(_ category: PersistenceCategory) -> some View {
        let count = viewModel.itemCount(for: category)
        let maxRisk = viewModel.highestRisk(for: category)
        let isBlocked = viewModel.isCoverageBlocked(for: category)

        return Label {
            HStack(spacing: 4) {
                Text(category.displayName)
                    .lineLimit(1)
                if isBlocked {
                    // A zero that means "could not look" must not read like a zero
                    // that means "clean".
                    Image(systemName: "lock.fill")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .accessibilityHidden(true)
                }
                if let risk = maxRisk, risk >= .medium {
                    // A glyph, not a bare colored dot: risk encoded by hue alone is
                    // invisible to a color-blind reader and to VoiceOver.
                    RiskIndicator(level: risk)
                }
            }
        } icon: {
            Image(systemName: category.sfSymbol)
        }
        // The native sidebar count: right-aligned, correctly announced, and styled
        // automatically in the selected row.
        .badge(count)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(accessibilityLabel(category, count: count,
                                               risk: maxRisk, blocked: isBlocked))
        .help(category.description)
    }

    private func accessibilityLabel(
        _ category: PersistenceCategory,
        count: Int,
        risk: RiskLevel?,
        blocked: Bool
    ) -> String {
        var parts = ["\(category.displayName), \(count) items"]
        if let risk, risk >= .medium {
            parts.append("highest risk \(risk.displayName)")
        }
        if blocked {
            parts.append("coverage incomplete, needs privileges")
        }
        return parts.joined(separator: ", ")
    }
}
