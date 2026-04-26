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

        // In headless (CLI) mode without root, skip scanners that require
        // elevated privileges — they may trigger GUI authorization prompts.
        let isHeadless = ProcessInfo.processInfo.environment["LAUNCHAUDIT_HEADLESS"] != nil
        let isRoot = getuid() == 0

        // Run all scanners concurrently
        var perScannerTimings: [PersistenceCategory: TimeInterval] = [:]
        await withTaskGroup(of: ScannerOutput.self) { group in
            for scanner in scanners {
                if isHeadless && !isRoot && scanner.requiresPrivilege {
                    // Record a permission-denied error instead of running
                    group.addTask {
                        ScannerOutput(
                            category: scanner.category,
                            items: [],
                            errors: [ScanError(
                                category: scanner.category,
                                message: "Skipped — requires root privileges (run with sudo)",
                                isPermissionDenied: true
                            )],
                            duration: 0
                        )
                    }
                    continue
                }

                group.addTask {
                    let started = Date()
                    do {
                        let items = try await scanner.scan()
                        return ScannerOutput(
                            category: scanner.category,
                            items: items,
                            errors: [],
                            duration: Date().timeIntervalSince(started)
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
                            errors: [scanError],
                            duration: Date().timeIntervalSince(started)
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
                perScannerTimings[output.category] = output.duration
            }
        }
        progress.scannerTimings = perScannerTimings

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

        // Collect indices that actually need verification, plus a single
        // bulk-stat per path so SigningVerifier doesn't repeat the syscall.
        // Some items reuse the same executable (e.g. /usr/sbin/cron called by
        // many cron entries) — dedupe those into one verify call as well.
        struct Job {
            let index: Int
            let path: String
            let modDate: Date?
        }
        let jobs: [Job] = items.enumerated().compactMap { (index, item) in
            guard let execPath = item.executablePath,
                  PathUtilities.exists(execPath) else { return nil }
            // Single stat per path here — SigningVerifier accepts the result
            // via its `knownModDate` parameter, skipping its own internal stat.
            let modDate = PathUtilities.timestamps(for: execPath).modified
            return Job(index: index, path: execPath, modDate: modDate)
        }

        guard !jobs.isEmpty else { return results }

        let verifier = self.signingVerifier

        await withTaskGroup(of: (Int, SigningInfo).self) { group in
            var iterator = jobs.makeIterator()
            var inFlight = 0

            // Seed the group with up to maxConcurrency tasks
            while inFlight < maxConcurrency, let job = iterator.next() {
                group.addTask {
                    let info = verifier.verify(path: job.path, knownModDate: job.modDate)
                    return (job.index, info)
                }
                inFlight += 1
            }

            // As each task completes, add the next one
            for await (idx, info) in group {
                results[idx].signingInfo = info
                inFlight -= 1

                if let next = iterator.next() {
                    group.addTask {
                        let info = verifier.verify(path: next.path, knownModDate: next.modDate)
                        return (next.index, info)
                    }
                    inFlight += 1
                }
            }
        }

        // Persist any new entries so subsequent scans skip the heavy work.
        verifier.flushDiskCache()

        return results
    }
}

private struct ScannerOutput: Sendable {
    let category: PersistenceCategory
    let items: [PersistenceItem]
    let errors: [ScanError]
    let duration: TimeInterval
}

public struct ScanProgress: Sendable {
    public var totalScanners: Int = 0
    public var completedScanners: Int = 0
    public var completedCategories: Set<PersistenceCategory> = []
    public var itemsFound: Int = 0
    public var phase: ScanPhase = .scanning
    /// Per-scanner wall-clock duration. Populated after Phase 1 completes.
    /// Useful for spotting the slowest scanners on a given system without
    /// requiring an external profiler.
    public var scannerTimings: [PersistenceCategory: TimeInterval] = [:]

    /// Top-N scanners by duration, descending. Convenient for diagnostics.
    public func slowestScanners(limit: Int = 5) -> [(PersistenceCategory, TimeInterval)] {
        scannerTimings
            .sorted { $0.value > $1.value }
            .prefix(limit)
            .map { ($0.key, $0.value) }
    }

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
