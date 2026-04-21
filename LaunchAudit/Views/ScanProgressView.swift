import SwiftUI

struct ScanProgressView: View {
    @EnvironmentObject var viewModel: ScanViewModel

    var body: some View {
        ZStack {
            Color.black.opacity(0.3)
                .ignoresSafeArea()

            VStack(spacing: 20) {
                ProgressView(value: viewModel.progress.fractionComplete) {
                    Text(viewModel.progress.statusText)
                        .font(.headline)
                }
                .progressViewStyle(.linear)

                HStack {
                    Text("\(viewModel.progress.itemsFound) items found")
                        .foregroundStyle(.secondary)
                    Spacer()
                    Text("\(Int(viewModel.progress.fractionComplete * 100))%")
                        .foregroundStyle(.secondary)
                }
                .font(.caption)

                // Category group progress grid
                if !viewModel.progress.completedCategories.isEmpty {
                    CategoryProgressGrid(completedCategories: viewModel.progress.completedCategories)
                }
            }
            .padding(32)
            .frame(maxWidth: 500)
            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 16))
            .shadow(radius: 20)
        }
    }
}

// MARK: - Category Progress Grid

private struct CategoryProgressGrid: View {
    let completedCategories: Set<PersistenceCategory>

    private var groups: [CategoryGroup] {
        CategoryGroup.allCases.filter { group in
            group.categories.contains(where: { completedCategories.contains($0) })
        }
    }

    var body: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 140), spacing: 8)], spacing: 8) {
            ForEach(groups) { group in
                GroupProgressRow(
                    group: group,
                    completedCategories: completedCategories
                )
            }
        }
    }
}

// MARK: - Group Row

private struct GroupProgressRow: View {
    let group: CategoryGroup
    let completedCategories: Set<PersistenceCategory>

    private var categories: [PersistenceCategory] { group.categories }
    private var completedCount: Int { categories.filter { completedCategories.contains($0) }.count }
    private var isFullyComplete: Bool { completedCount == categories.count }

    var body: some View {
        HStack(spacing: 8) {
            // Mini ring indicator
            ZStack {
                Circle()
                    .stroke(.quaternary, lineWidth: 2)
                Circle()
                    .trim(from: 0, to: CGFloat(completedCount) / CGFloat(categories.count))
                    .stroke(
                        isFullyComplete ? Color.green : Color.accentColor,
                        style: StrokeStyle(lineWidth: 2, lineCap: .round)
                    )
                    .rotationEffect(.degrees(-90))

                if isFullyComplete {
                    Image(systemName: "checkmark")
                        .font(.system(size: 7, weight: .bold))
                        .foregroundStyle(.green)
                } else {
                    Text("\(completedCount)")
                        .font(.system(size: 8, weight: .semibold).monospacedDigit())
                        .foregroundStyle(.secondary)
                }
            }
            .frame(width: 20, height: 20)

            VStack(alignment: .leading, spacing: 2) {
                Text(group.rawValue)
                    .font(.caption2.weight(.medium))
                    .foregroundStyle(isFullyComplete ? .primary : .secondary)
                    .lineLimit(1)

                // Tiny icons for each category in group
                HStack(spacing: 2) {
                    ForEach(categories) { cat in
                        let done = completedCategories.contains(cat)
                        Circle()
                            .fill(done ? Color.green : Color.gray.opacity(0.25))
                            .frame(width: 5, height: 5)
                            .help(cat.displayName)
                    }
                }
            }

            Spacer(minLength: 0)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .background(
            isFullyComplete ? Color.green.opacity(0.06) : Color.clear,
            in: RoundedRectangle(cornerRadius: 6)
        )
        .animation(.easeOut(duration: 0.2), value: completedCount)
    }
}
