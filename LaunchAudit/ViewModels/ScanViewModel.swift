import SwiftUI
import Combine

@MainActor
public final class ScanViewModel: ObservableObject {
    @Published public var lastResult: ScanResult?
    @Published public var isScanning = false
    @Published public var progress = ScanProgress()
    @Published public var searchText = ""
    @Published public var minimumRiskFilter: RiskLevel?
    @Published public var showOnlyUnsigned = false
    @Published public var showOnlyThirdParty = false
    @Published public var hideAppleSigned = true
    @Published public var hideEmptyCategories = true
    @Published public var showExportSheet = false
    @Published public var exportFormat: ExportFormat = .json

    private let coordinator = ScanCoordinator()

    public init() {}

    public func startScan() async {
        isScanning = true

        #if DEMO_MODE
        // Simulate a brief scan delay then load demo data
        try? await Task.sleep(for: .seconds(1.5))
        lastResult = DemoDataProvider.makeScanResult()
        progress.phase = .complete
        #else
        // Forward progress from coordinator
        let task = Task {
            while !Task.isCancelled {
                self.progress = coordinator.progress
                try? await Task.sleep(for: .milliseconds(100))
            }
        }

        let result = await coordinator.performFullScan()
        task.cancel()

        lastResult = result
        progress = coordinator.progress
        #endif
        isScanning = false
    }

    // MARK: - Filtering

    /// All items after applying the Apple-signed filter (used by dashboard and counts).
    public var displayItems: [PersistenceItem] {
        guard let result = lastResult else { return [] }
        if hideAppleSigned {
            return result.items.filter { !$0.isAppleSignedAndNotarized }
        }
        return result.items
    }

    public func filteredItems(for category: PersistenceCategory) -> [PersistenceItem] {
        var items = displayItems.filter { $0.category == category }

        if let minRisk = minimumRiskFilter {
            items = items.filter { $0.riskLevel >= minRisk }
        }

        if showOnlyUnsigned {
            items = items.filter { $0.signingInfo?.isSigned != true }
        }

        if showOnlyThirdParty {
            items = items.filter { !$0.source.isApple }
        }

        if !searchText.isEmpty {
            let query = searchText.lowercased()
            items = items.filter { item in
                item.name.lowercased().contains(query)
                || (item.label?.lowercased().contains(query) ?? false)
                || (item.configPath?.lowercased().contains(query) ?? false)
                || (item.executablePath?.lowercased().contains(query) ?? false)
                || item.source.displayName.lowercased().contains(query)
            }
        }

        return items
    }

    public func itemCount(for category: PersistenceCategory) -> Int {
        displayItems.filter { $0.category == category }.count
    }

    public func highestRisk(for category: PersistenceCategory) -> RiskLevel? {
        displayItems
            .filter { $0.category == category }
            .map(\.riskLevel)
            .max()
    }
}
