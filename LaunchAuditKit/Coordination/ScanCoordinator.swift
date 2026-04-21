import Foundation

/// Orchestrates all scanners, runs them in parallel, and aggregates results.
@MainActor
public final class ScanCoordinator: ObservableObject {
    @Published public var isScanning = false
    @Published public var progress: ScanProgress = ScanProgress()
    @Published public var lastResult: ScanResult?

    private let signingVerifier = SigningVerifier()
    private let riskAnalyzer = RiskAnalyzer()

    /// All registered scanners.
    public let scanners: [any PersistenceScanner] = [
        LaunchDaemonScanner(),
        LaunchAgentScanner(),
        LoginItemScanner(),
        BTMScanner(),
        CronScanner(),
        PeriodicScanner(),
        LoginHookScanner(),
        StartupItemScanner(),
        KextScanner(),
        SystemExtensionScanner(),
        AuthPluginScanner(),
        DirectoryServicesScanner(),
        PrivilegedHelperScanner(),
        ProfileScanner(),
        ScriptingAdditionScanner(),
        InputMethodScanner(),
        SpotlightScanner(),
        QuickLookScanner(),
        EmondScanner(),
        DylibInjectionScanner(),
        ShellProfileScanner(),
        FolderActionScanner(),
        RcScriptScanner(),
        PAMScanner(),
        NetworkScriptScanner(),
        XPCServiceScanner(),
        ScreenSaverScanner(),
        AudioPluginScanner(),
        PrinterPluginScanner(),
        ReopenAtLoginScanner(),
        AppExtensionScanner(),
        BrowserExtensionScanner(),
        AutomatorScanner(),
        WidgetScanner(),
        DockTilePluginScanner(),
        FilelessProcessScanner(),
    ]

    public init() {}

    /// Run a full scan across all persistence categories.
    public func performFullScan() async -> ScanResult {
        isScanning = true
        let startTime = Date()
        progress = ScanProgress(totalScanners: scanners.count)

        var allItems: [PersistenceItem] = []
        var allErrors: [ScanError] = []

        // Run all scanners concurrently
        await withTaskGroup(of: ScannerOutput.self) { group in
            for scanner in scanners {
                group.addTask {
                    do {
                        let items = try await scanner.scan()
                        return ScannerOutput(
                            category: scanner.category,
                            items: items,
                            errors: []
                        )
                    } catch {
                        let scanError = ScanError(
                            category: scanner.category,
                            message: error.localizedDescription,
                            isPermissionDenied: (error as NSError).code == 13
                        )
                        return ScannerOutput(
                            category: scanner.category,
                            items: [],
                            errors: [scanError]
                        )
                    }
                }
            }

            for await output in group {
                allItems.append(contentsOf: output.items)
                allErrors.append(contentsOf: output.errors)
                progress.completedScanners += 1
                progress.completedCategories.insert(output.category)
                progress.itemsFound = allItems.count
            }
        }

        // Phase 2: Verify code signatures in parallel
        progress.phase = .verifyingSignatures
        allItems = await verifySignatures(for: allItems)

        // Phase 3: Analyze risk
        progress.phase = .analyzingRisk
        allItems = allItems.map { riskAnalyzer.analyze($0) }

        let duration = Date().timeIntervalSince(startTime)
        let result = ScanResult(
            items: allItems,
            errors: allErrors,
            scanDuration: duration
        )

        lastResult = result
        isScanning = false
        progress.phase = .complete
        return result
    }

    /// Verify code signatures for items that have an executable path.
    /// Uses a sliding-window approach: keep up to `maxConcurrency` tasks in flight,
    /// drain one result before adding the next.
    private func verifySignatures(for items: [PersistenceItem]) async -> [PersistenceItem] {
        let maxConcurrency = 12
        var results = items

        // Collect indices that actually need verification
        let verifiable = items.enumerated().compactMap { (index, item) -> (Int, String)? in
            guard let execPath = item.executablePath,
                  PathUtilities.exists(execPath) else { return nil }
            return (index, execPath)
        }

        guard !verifiable.isEmpty else { return results }

        // SigningVerifier is no longer an actor — calls run in parallel without serialization
        let verifier = self.signingVerifier

        await withTaskGroup(of: (Int, SigningInfo).self) { group in
            var iterator = verifiable.makeIterator()
            var inFlight = 0

            // Seed the group with up to maxConcurrency tasks
            while inFlight < maxConcurrency, let (index, path) = iterator.next() {
                group.addTask {
                    let info = verifier.verify(path: path)
                    return (index, info)
                }
                inFlight += 1
            }

            // As each task completes, add the next one
            for await (idx, info) in group {
                results[idx].signingInfo = info
                inFlight -= 1

                if let (nextIndex, nextPath) = iterator.next() {
                    group.addTask {
                        let info = verifier.verify(path: nextPath)
                        return (nextIndex, info)
                    }
                    inFlight += 1
                }
            }
        }

        return results
    }
}

private struct ScannerOutput: Sendable {
    let category: PersistenceCategory
    let items: [PersistenceItem]
    let errors: [ScanError]
}

public struct ScanProgress: Sendable {
    public var totalScanners: Int = 0
    public var completedScanners: Int = 0
    public var completedCategories: Set<PersistenceCategory> = []
    public var itemsFound: Int = 0
    public var phase: ScanPhase = .scanning

    public var fractionComplete: Double {
        guard totalScanners > 0 else { return 0 }
        switch phase {
        case .scanning:
            return Double(completedScanners) / Double(totalScanners) * 0.7
        case .verifyingSignatures:
            return 0.7 + 0.2
        case .analyzingRisk:
            return 0.9 + 0.1
        case .complete:
            return 1.0
        }
    }

    public var statusText: String {
        switch phase {
        case .scanning:
            return "Scanning persistence mechanisms (\(completedScanners)/\(totalScanners))..."
        case .verifyingSignatures:
            return "Verifying code signatures..."
        case .analyzingRisk:
            return "Analyzing risk levels..."
        case .complete:
            return "Scan complete — \(itemsFound) items found"
        }
    }
}

public enum ScanPhase: Sendable {
    case scanning
    case verifyingSignatures
    case analyzingRisk
    case complete
}
