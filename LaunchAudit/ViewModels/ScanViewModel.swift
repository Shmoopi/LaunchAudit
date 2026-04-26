import SwiftUI
import Combine
import ServiceManagement

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
    /// Surfaces the privileged-helper status to the UI. `requiresApproval`
    /// means the user needs to enable the daemon in System Settings
    /// → General → Login Items & Extensions. Other values are informational.
    @Published public var privilegeStatus: PrivilegeStatus = .unknown

    /// Per-session dismissal flag for the privilege banner. Reset on each
    /// new scan attempt so the user is re-informed if the situation hasn't
    /// changed — but not nagged within a single session if they choose to
    /// proceed without elevation.
    @Published public var privilegeBannerDismissed = false

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
        // Register the privileged helper before scanning. First-launch users
        // will see macOS's "Background Items Added" prompt and be directed
        // to System Settings to approve. If they decline, the scan still
        // runs — privileged scanners just return empty (handled per-scanner).
        await ensureHelperRegistered()

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

    /// Idempotent — calling repeatedly is cheap once the daemon is enabled.
    /// Errors are non-fatal: scanning proceeds without privileged data.
    private func ensureHelperRegistered() async {
        // Reset per-session dismissal so the banner can re-appear if the
        // user toggled the daemon off in System Settings between scans.
        resetPrivilegeBannerDismissal()
        do {
            try await PrivilegeBroker.shared.installHelperIfNeeded()
            privilegeStatus = .enabled
        } catch PrivilegeBrokerError.requiresApproval {
            privilegeStatus = .requiresApproval
        } catch {
            privilegeStatus = .failed(error.localizedDescription)
        }
    }

    // MARK: - Privilege banner state

    /// True when the UI should surface the "needs administrator access"
    /// banner to the user.
    public var shouldShowPrivilegeBanner: Bool {
        guard !privilegeBannerDismissed else { return false }
        switch privilegeStatus {
        case .requiresApproval, .failed:
            return true
        case .unknown, .enabled:
            return false
        }
    }

    /// Localized failure message when the helper installation failed.
    /// Returns nil for any status other than `.failed`.
    public var privilegeFailureMessage: String? {
        if case .failed(let msg) = privilegeStatus { return msg }
        return nil
    }

    public func dismissPrivilegeBanner() {
        privilegeBannerDismissed = true
    }

    public func resetPrivilegeBannerDismissal() {
        privilegeBannerDismissed = false
    }

    /// Open System Settings → Login Items so the user can enable the helper.
    /// SMAppService handles the deep-link in a single call from macOS 13+.
    public func openLoginItemsSettings() {
        SMAppService.openSystemSettingsLoginItems()
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

/// Status of the privileged helper from the user's perspective.
public enum PrivilegeStatus: Sendable, Equatable {
    case unknown
    case enabled
    /// User must approve the daemon in System Settings → Login Items.
    case requiresApproval
    case failed(String)
}
