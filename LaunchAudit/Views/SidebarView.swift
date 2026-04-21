import SwiftUI

struct SidebarView: View {
    @EnvironmentObject var viewModel: ScanViewModel
    @Binding var selectedCategory: PersistenceCategory?
    @Binding var showDashboard: Bool

    var body: some View {
        List(selection: $selectedCategory) {
            // Dashboard button
            Button {
                showDashboard = true
                selectedCategory = nil
            } label: {
                Label("Dashboard", systemImage: "gauge.with.dots.needle.33percent")
            }
            .buttonStyle(.plain)
            .padding(.vertical, 4)
            .fontWeight(showDashboard ? .semibold : .regular)

            Divider()

            // Categories grouped
            ForEach(CategoryGroup.allCases) { group in
                Section(group.rawValue) {
                    ForEach(group.categories) { cat in
                        let count = viewModel.itemCount(for: cat)
                        let maxRisk = viewModel.highestRisk(for: cat)
                        categoryRow(cat, count: count, maxRisk: maxRisk)
                            .tag(cat)
                    }
                }
            }
        }
        .listStyle(.sidebar)
        .onChange(of: selectedCategory) { _, newValue in
            if newValue != nil { showDashboard = false }
        }
    }

    private func categoryRow(_ category: PersistenceCategory, count: Int, maxRisk: RiskLevel?) -> some View {
        HStack {
            Label(category.displayName, systemImage: category.sfSymbol)
                .lineLimit(1)

            Spacer()

            Text("\(count)")
                .font(.caption)
                .foregroundStyle(.secondary)
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(.quaternary, in: Capsule())

            if let risk = maxRisk, risk >= .medium {
                Circle()
                    .fill(risk.color)
                    .frame(width: 8, height: 8)
            }
        }
    }
}
