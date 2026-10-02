import SwiftUI
import Combine
import ServiceManagement

@MainActor
public final class ScanViewModel: ObservableObject {
    @Published public var lastResult: ScanResult? { didSet { recomputeFilteredItems() } }
    @Published public var isScanning = false
    @Published public var searchText = "" { didSet { recomputeFilteredItems() } }
    @Published public var minimumRiskFilter: RiskLevel? { didSet { recomputeFilteredItems() } }
    @Published public var showOnlyUnsigned = false { didSet { recomputeFilteredItems() } }
    @Published public var showOnlyThirdParty = false { didSet { recomputeFilteredItems() } }
    @Published public var hideAppleSigned = true { didSet { recomputeFilteredItems() } }
    @Published public var hideEmptyCategories = true
    @Published public var showExportSheet = false
    @Published public var exportFormat: ExportFormat = .json
    /// Surfaces the privileged-helper status to the UI. `requiresApproval`
    /// means the user needs to enable the daemon in System Settings
    /// → General → Login Items & Extensions. Other values are informational.
    @Published public var privilegeStatus: PrivilegeStatus = .unknown

    /// Set when something the user asked for failed. Rendered as an alert —
    /// previously every failure in the app was a `print` to the console.
    @Published public var alert: UserFacingAlert?

    /// Per-session dismissal flag for the privilege banner. Reset on each
    /// new scan attempt so the user is re-informed if the situation hasn't
    /// changed — but not nagged within a single session if they choose to
    /// proceed without elevation.
    @Published public var privilegeBannerDismissed = false

    /// Scan progress lives in its own object so the 10 Hz updates during a scan
    /// redraw only the progress indicator. As a `@Published` property here, every
    /// tick invalidated the sidebar, dashboard and table — each of which re-ran
    /// every filter over every item.
    public let scanProgress = ScanProgressModel()

    // Filter results, recomputed once when an input changes rather than on every
    // property access. The sidebar alone used to re-filter the full item list
    // roughly 100 times per render.
    public private(set) var displayItems: [PersistenceItem] = []
    public private(set) var filteredItems: [PersistenceItem] = []
    private var filteredByCategory: [PersistenceCategory: [PersistenceItem]] = [:]
    private var unfilteredCountByCategory: [PersistenceCategory: Int] = [:]
    private var highestRiskByCategory: [PersistenceCategory: RiskLevel] = [:]
    private var blockedCategories: Set<PersistenceCategory> = []
    /// Dashboard figures, over `displayItems`.
    private(set) var dashboardStats = DashboardStats()

    private let coordinator = ScanCoordinator()
    private var scanTask: Task<Void, Never>?

    public init() {}

    // MARK: - Scanning

    /// Start a scan, replacing any in flight.
    ///
    /// Held as a task so it can be cancelled: the scan used to be unstoppable, with
    /// a full-window modal scrim and no Cancel button, so a wedged scan left Force
    /// Quit as the only exit.
    public func startScanTask() {
        guard !isScanning else { return }
        scanTask?.cancel()
        scanTask = Task { await startScan() }
    }

    public func cancelScan() {
        scanTask?.cancel()
    }

    public func startScan() async {
        guard !isScanning else { return }
        isScanning = true
        defer { isScanning = false }

        #if DEMO_MODE
        scanProgress.reset()
        try? await Task.sleep(for: .seconds(1.5))
        lastResult = DemoDataProvider.makeScanResult()
        #else
        scanProgress.reset()
        await ensureHelperRegistered()

        // Mirror the coordinator's progress into the progress model.
        let mirror = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                self.scanProgress.update(from: self.coordinator.progress)
                try? await Task.sleep(for: .milliseconds(100))
            }
        }
        defer { mirror.cancel() }

        let result = await coordinator.performFullScan()
        lastResult = result
        scanProgress.update(from: coordinator.progress)
        #endif
    }

    /// Idempotent — calling repeatedly is cheap once the daemon is enabled.
    /// Errors are non-fatal: scanning proceeds, and the affected categories report
    /// their own coverage gaps.
    private func ensureHelperRegistered() async {
        resetPrivilegeBannerDismissal()
        do {
            // `installHelperIfNeeded` re-reads the status after registering.
            // Assuming success meant a first-run user was recorded as `.enabled`
            // while the daemon sat unapproved, so the banner explaining what to do
            // never appeared on the run where it mattered most.
            let status = try await PrivilegeBroker.shared.installHelperIfNeeded()
            privilegeStatus = status == .enabled ? .enabled : .requiresApproval
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

    /// Every filter currently narrowing the view, in words.
    public var activeFilterDescriptions: [String] {
        var descriptions: [String] = []
        if hideAppleSigned { descriptions.append("Apple system items hidden") }
        if let minimumRiskFilter {
            descriptions.append("\(minimumRiskFilter.displayName) risk and above")
        }
        if showOnlyUnsigned { descriptions.append("Unsigned only") }
        if showOnlyThirdParty { descriptions.append("Third-party only") }
        if !searchText.isEmpty { descriptions.append("Search: “\(searchText)”") }
        return descriptions
    }

    public var hasActiveFilters: Bool { !activeFilterDescriptions.isEmpty }

    public func clearFilters() {
        hideAppleSigned = false
        minimumRiskFilter = nil
        showOnlyUnsigned = false
        showOnlyThirdParty = false
        searchText = ""
    }

    /// Rebuild every filtered view of the results.
    ///
    /// A high or critical finding is never hidden by the Apple filter: "hide Apple
    /// system items" means "hide the routine OS rows", not "suppress serious
    /// findings that happen to look Apple".
    private func recomputeFilteredItems() {
        let all = lastResult?.items ?? []
        let display = hideAppleSigned
            ? all.filter { !$0.isVerifiedAppleSoftware || $0.riskLevel >= .high }
            : all

        let query = searchText.trimmingCharacters(in: .whitespaces)
        let filtered = display.filter { item in
            if let minimumRiskFilter, item.riskLevel < minimumRiskFilter { return false }
            if showOnlyUnsigned, item.signingInfo?.isSigned == true { return false }
            if showOnlyThirdParty, item.source.isApple { return false }
            if !query.isEmpty, !Self.item(item, matches: query) { return false }
            return true
        }

        displayItems = display
        filteredItems = filtered
        filteredByCategory = Dictionary(grouping: filtered, by: \.category)
        unfilteredCountByCategory = all.reduce(into: [:]) { $0[$1.category, default: 0] += 1 }
        highestRiskByCategory = filteredByCategory.compactMapValues { $0.map(\.riskLevel).max() }
        blockedCategories = lastResult?.categoriesBlockedByPermissions ?? []
        dashboardStats = DashboardStats(items: display)
    }

    private static func item(_ item: PersistenceItem, matches query: String) -> Bool {
        item.name.localizedCaseInsensitiveContains(query)
            || (item.label?.localizedCaseInsensitiveContains(query) ?? false)
            || (item.configPath?.localizedCaseInsensitiveContains(query) ?? false)
            || (item.executablePath?.localizedCaseInsensitiveContains(query) ?? false)
            || item.source.displayName.localizedCaseInsensitiveContains(query)
            || item.category.displayName.localizedCaseInsensitiveContains(query)
    }

    public func filteredItems(for category: PersistenceCategory) -> [PersistenceItem] {
        filteredByCategory[category] ?? []
    }

    /// Count shown in the sidebar. Applies the same filters the list does, so the
    /// badge and the list it leads to always agree.
    public func itemCount(for category: PersistenceCategory) -> Int {
        filteredByCategory[category]?.count ?? 0
    }

    /// Total number of items in a category before filtering — used to explain an
    /// empty list ("12 items, none match the active filters").
    public func unfilteredCount(for category: PersistenceCategory) -> Int {
        unfilteredCountByCategory[category] ?? 0
    }

    public func highestRisk(for category: PersistenceCategory) -> RiskLevel? {
        highestRiskByCategory[category]
    }

    /// Whether this category's results are known to be incomplete.
    public func isCoverageBlocked(for category: PersistenceCategory) -> Bool {
        blockedCategories.contains(category)
    }
}

/// Live scan progress, observed only by the views that draw it.
@MainActor
public final class ScanProgressModel: ObservableObject {
    @Published public private(set) var fractionComplete: Double = 0
    @Published public private(set) var statusText: String = ""

    /// Publish only when something visible changed; the coordinator is polled at
    /// 10 Hz and most ticks carry no new information.
    func update(from progress: ScanProgress) {
        let fraction = (progress.fractionComplete * 100).rounded() / 100
        if fraction != fractionComplete { fractionComplete = fraction }
        let text = progress.statusText
        if text != statusText { statusText = text }
    }

    func reset() {
        fractionComplete = 0
        statusText = "Preparing scan…"
    }
}

/// A message that needs the user's attention.
public struct UserFacingAlert: Identifiable, Sendable {
    public let id = UUID()
    public let title: String
    public let message: String

    public init(title: String, message: String) {
        self.title = title
        self.message = message
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
