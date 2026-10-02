import Foundation

/// Options controlling a scan.
///
/// Replaces the previous `LAUNCHAUDIT_HEADLESS` environment-variable coupling,
/// which was read from three unrelated files and could not be exercised by a test.
public struct ScanOptions: Sendable {
    /// Restrict the scan to these categories. `nil` scans everything.
    ///
    /// Previously `--category` ran all 36 scanners and filtered afterwards, so a
    /// targeted scan cost the same as a full one.
    public var categories: Set<PersistenceCategory>?
    /// Suppress anything that could raise a GUI consent prompt (Apple Events,
    /// for instance). Set for CLI runs.
    public var avoidInteractivePrompts: Bool
    /// Hard ceiling per scanner. A wedged read degrades one category instead of
    /// hanging the whole run.
    public var perScannerTimeout: TimeInterval

    public init(
        categories: Set<PersistenceCategory>? = nil,
        avoidInteractivePrompts: Bool = false,
        perScannerTimeout: TimeInterval = 30
    ) {
        self.categories = categories
        self.avoidInteractivePrompts = avoidInteractivePrompts
        self.perScannerTimeout = perScannerTimeout
    }

    public static let `default` = ScanOptions()

    /// Options for a headless CLI run.
    public static func headless(
        categories: Set<PersistenceCategory>? = nil
    ) -> ScanOptions {
        ScanOptions(categories: categories, avoidInteractivePrompts: true)
    }
}

/// Orchestrates all scanners, runs them in parallel, and aggregates results.
@MainActor
public final class ScanCoordinator: ObservableObject {
    @Published public var isScanning = false
    @Published public var progress: ScanProgress = ScanProgress()
    @Published public var lastResult: ScanResult?

    private let signingVerifier = SigningVerifier()
    private let riskAnalyzer = RiskAnalyzer()

    /// All registered scanners.
    public let scanners: [any PersistenceScanner]

    public init(scanners: [any PersistenceScanner]? = nil) {
        self.scanners = scanners ?? Self.defaultScanners()
    }

    /// The standard scanner set. Exposed so tests can build a coordinator around
    /// a subset instead of running every scanner against the live machine.
    public static func defaultScanners() -> [any PersistenceScanner] {
        [
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
    }

    /// Run a scan. Honors task cancellation at every phase boundary.
    ///
    /// Re-entrant calls are rejected: two concurrent scans on one coordinator
    /// interleave their progress counters, and whichever finishes first clears
    /// `isScanning` while the other is still running.
    public func performFullScan(options: ScanOptions = .default) async -> ScanResult {
        guard !isScanning else {
            return lastResult ?? ScanResult(items: [], errors: [], scanDuration: 0)
        }
        isScanning = true
        defer { isScanning = false }

        ScanEnvironment.shared.apply(options)
        let startTime = Date()

        let active = scanners.filter { scanner in
            options.categories.map { $0.contains(scanner.category) } ?? true
        }
        progress = ScanProgress(totalScanners: active.count)

        var allItems: [PersistenceItem] = []
        var allErrors: [ScanError] = []

        let timeout = options.perScannerTimeout

        // Phase 1: run all scanners concurrently.
        //
        // Privileged scanners are **not** skipped when the process is unprivileged.
        // They route through `PrivilegedCommand`, which uses the approved root
        // helper when direct access is unavailable — skipping them here is what made
        // the helper unreachable from the GUI in the first place. Each scanner
        // reports its own coverage error if no route works.
        var perScannerTimings: [PersistenceCategory: TimeInterval] = [:]
        await withTaskGroup(of: ScannerOutput.self) { group in
            for scanner in active {
                group.addTask {
                    let started = Date()
                    do {
                        let outcome = try await Self.withTimeout(seconds: timeout) {
                            try await scanner.scan()
                        }
                        return ScannerOutput(
                            category: scanner.category,
                            items: outcome.items,
                            errors: outcome.errors,
                            duration: Date().timeIntervalSince(started)
                        )
                    } catch is ScanTimeout {
                        return ScannerOutput(
                            category: scanner.category,
                            items: [],
                            errors: [ScanError(
                                category: scanner.category,
                                message: "Timed out after \(Int(timeout))s — a path may be "
                                    + "unreadable or a special file (FIFO or device)",
                                isPermissionDenied: false
                            )],
                            duration: Date().timeIntervalSince(started)
                        )
                    } catch {
                        let nsError = error as NSError
                        let scanError = ScanError(
                            category: scanner.category,
                            message: error.localizedDescription,
                            isPermissionDenied: nsError.code == Int(EACCES)
                                || nsError.code == NSFileReadNoPermissionError
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
                if Task.isCancelled { group.cancelAll() }
            }
        }
        progress.scannerTimings = perScannerTimings

        if Task.isCancelled {
            return finish(items: allItems, errors: allErrors, start: startTime,
                          options: options, cancelled: true)
        }

        // Phase 2: verify code signatures in parallel.
        progress.phase = .verifyingSignatures
        allItems = await verifySignatures(for: allItems)

        if Task.isCancelled {
            return finish(items: allItems, errors: allErrors, start: startTime,
                          options: options, cancelled: true)
        }

        // Phase 3: analyze risk.
        progress.phase = .analyzingRisk
        progress.analysisTotal = allItems.count
        progress.analysisCompleted = 0
        var analyzed: [PersistenceItem] = []
        analyzed.reserveCapacity(allItems.count)
        for item in allItems {
            analyzed.append(riskAnalyzer.analyze(item))
            progress.analysisCompleted += 1
        }

        return finish(items: analyzed, errors: allErrors, start: startTime,
                      options: options, cancelled: false)
    }

    private func finish(
        items: [PersistenceItem],
        errors: [ScanError],
        start: Date,
        options: ScanOptions,
        cancelled: Bool
    ) -> ScanResult {
        var errors = errors
        if cancelled {
            errors.append(ScanError(
                category: nil,
                message: "Scan cancelled before completion — results are partial",
                isPermissionDenied: false
            ))
        }
        let result = ScanResult(
            items: items,
            errors: errors,
            scanDuration: Date().timeIntervalSince(start),
            ranAsRoot: PathUtilities.isRoot,
            scannedCategories: Set((options.categories ?? Set(PersistenceCategory.allCases))),
            hadAuthoritativeLaunchdState: LaunchdStateResolver.shared.hasAuthoritativeState
        )
        lastResult = result
        progress.phase = .complete
        return result
    }

    /// Verify code signatures for items that have something to verify.
    ///
    /// Work is deduplicated by path: many cron entries share `/usr/sbin/cron`, and
    /// many launchd jobs share an interpreter. The previous implementation built
    /// one job per item despite a comment claiming otherwise, so it also paid one
    /// `stat` per item.
    private func verifySignatures(for items: [PersistenceItem]) async -> [PersistenceItem] {
        let maxConcurrency = 12
        var results = items

        // path -> indices of every item that resolves to it.
        var pathToIndices: [String: [Int]] = [:]
        for (index, item) in items.enumerated() {
            // Verify the interpreted script when there is one, so a shell-fronted
            // item is judged on its payload rather than on /bin/sh; and the bundle
            // itself when it has no executable.
            guard let path = item.signatureTargetPath,
                  PathUtilities.exists(path) else { continue }
            pathToIndices[path, default: []].append(index)
        }

        guard !pathToIndices.isEmpty else { return results }

        struct Job: Sendable {
            let path: String
            let modDate: Date?
        }
        let jobs = pathToIndices.keys.map { path in
            Job(path: path, modDate: PathUtilities.timestamps(for: path).modified)
        }

        let verifier = self.signingVerifier
        progress.verificationTotal = jobs.count
        progress.verificationCompleted = 0

        // Verification runs on a dedicated dispatch queue, NOT on the Swift
        // concurrency cooperative pool.
        //
        // `SecStaticCodeCheckValidity` blocks internally on a libdispatch group
        // while it hashes and validates. Running it from `withTaskGroup` put a
        // blocking call on every cooperative thread at once, and Security.framework
        // then could not get a worker thread to finish the work those threads were
        // waiting on — a self-inflicted deadlock that hung the entire scan. Blocking
        // a cooperative thread is unsupported; here the threads are ours to block.
        let counter = ProgressCounter()
        let verified: [String: SigningInfo] = await withCheckedContinuation { continuation in
            verificationQueue.async {
                let slots = DispatchSemaphore(value: maxConcurrency)
                let group = DispatchGroup()
                let collected = VerificationResults()

                for job in jobs {
                    slots.wait()
                    group.enter()
                    verificationQueue.async {
                        let info = verifier.verify(path: job.path, knownModDate: job.modDate)
                        collected.store(job.path, info)
                        counter.increment()
                        slots.signal()
                        group.leave()
                    }
                }

                group.wait()
                continuation.resume(returning: collected.snapshot())
            }
        }

        // Mirror the counter into published progress once the phase is done; a
        // lightweight poller updates it while the phase runs (see `startScan`).
        progress.verificationCompleted = counter.value

        for (path, info) in verified {
            for index in pathToIndices[path] ?? [] {
                results[index].signingInfo = info
            }
        }

        return results
    }


    /// Thread-safe accumulator for verification results.
    private final class VerificationResults: @unchecked Sendable {
        private let lock = NSLock()
        private var storage: [String: SigningInfo] = [:]

        func store(_ path: String, _ info: SigningInfo) {
            lock.lock()
            storage[path] = info
            lock.unlock()
        }

        func snapshot() -> [String: SigningInfo] {
            lock.lock()
            defer { lock.unlock() }
            return storage
        }
    }

    /// Thread-safe completion counter, read by the progress poller.
    final class ProgressCounter: @unchecked Sendable {
        private let lock = NSLock()
        private var count = 0

        func increment() {
            lock.lock()
            count += 1
            lock.unlock()
        }

        var value: Int {
            lock.lock()
            defer { lock.unlock() }
            return count
        }
    }

    // MARK: - Timeout helper

    struct ScanTimeout: Error {}

    /// Run `work`, throwing `ScanTimeout` if it outlasts `seconds`.
    ///
    /// Deliberately **not** a task group racing the work against a sleep. A task
    /// group awaits all of its children when the scope exits, so if the work is
    /// stuck somewhere that does not observe cancellation — a blocking `read`, a
    /// subprocess that never exits, an XPC reply that never arrives — the group
    /// would wait for it forever and the timeout would accomplish nothing.
    ///
    /// Running the work as an unstructured task lets the timeout return while the
    /// stuck task is merely cancelled and abandoned.
    static func withTimeout<T: Sendable>(
        seconds: TimeInterval,
        _ work: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        let state = TimeoutState<T>()

        return try await withCheckedThrowingContinuation { continuation in
            let workTask = Task {
                do {
                    let value = try await work()
                    state.finish(continuation, .success(value))
                } catch {
                    state.finish(continuation, .failure(error))
                }
            }

            Task {
                try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                if state.finish(continuation, .failure(ScanTimeout())) {
                    workTask.cancel()
                }
            }
        }
    }

    /// One-shot resumption guard shared by the work and timeout tasks.
    private final class TimeoutState<T: Sendable>: @unchecked Sendable {
        private let lock = NSLock()
        private var resumed = false

        @discardableResult
        func finish(
            _ continuation: CheckedContinuation<T, Error>,
            _ result: Result<T, Error>
        ) -> Bool {
            lock.lock()
            if resumed {
                lock.unlock()
                return false
            }
            resumed = true
            lock.unlock()
            continuation.resume(with: result)
            return true
        }
    }
}

/// Dedicated pool for code-signature verification. See `verifySignatures`.
///
/// A file-scope constant rather than a `static` on the `@MainActor` coordinator, so
/// it can be referenced from the `Sendable` closures that do the work.
private let verificationQueue = DispatchQueue(
    label: "net.shmoopi.launchaudit.verification",
    qos: .userInitiated,
    attributes: .concurrent
)

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
    public var verificationTotal: Int = 0
    public var verificationCompleted: Int = 0
    public var analysisTotal: Int = 0
    public var analysisCompleted: Int = 0
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

    /// Fraction of the whole scan completed.
    ///
    /// Each phase now reports its own real progress. Previously signature
    /// verification — usually the longest phase — returned a constant 0.9, and
    /// risk analysis returned 1.0 while still running.
    public var fractionComplete: Double {
        guard totalScanners > 0 else { return 0 }
        let scanShare = 0.7, verifyShare = 0.25, analyzeShare = 0.05

        switch phase {
        case .scanning:
            return Double(completedScanners) / Double(totalScanners) * scanShare
        case .verifyingSignatures:
            guard verificationTotal > 0 else { return scanShare }
            let fraction = Double(verificationCompleted) / Double(verificationTotal)
            return scanShare + fraction * verifyShare
        case .analyzingRisk:
            guard analysisTotal > 0 else { return scanShare + verifyShare }
            let fraction = Double(analysisCompleted) / Double(analysisTotal)
            return scanShare + verifyShare + fraction * analyzeShare
        case .complete:
            return 1.0
        }
    }

    public var statusText: String {
        switch phase {
        case .scanning:
            return "Scanning persistence mechanisms (\(completedScanners)/\(totalScanners))…"
        case .verifyingSignatures:
            if verificationTotal > 0 {
                return "Verifying code signatures (\(verificationCompleted)/\(verificationTotal))…"
            }
            return "Verifying code signatures…"
        case .analyzingRisk:
            return "Analyzing risk levels…"
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
