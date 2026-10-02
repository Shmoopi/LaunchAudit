import Foundation

/// What a scanner found, and what it could not look at.
///
/// Scanners previously returned only `[PersistenceItem]`, so a directory that
/// could not be read produced zero items and zero errors — indistinguishable
/// from a directory that was genuinely empty. For an auditor that is the most
/// expensive failure mode there is: the user cannot tell "clean" from "blind".
public struct ScanOutcome: Sendable {
    public var items: [PersistenceItem]
    public var errors: [ScanError]

    public init(items: [PersistenceItem] = [], errors: [ScanError] = []) {
        self.items = items
        self.errors = errors
    }

    public static let empty = ScanOutcome()

    public mutating func merge(_ other: ScanOutcome) {
        items.append(contentsOf: other.items)
        errors.append(contentsOf: other.errors)
    }

    public mutating func merge(_ pair: ([PersistenceItem], [ScanError])) {
        items.append(contentsOf: pair.0)
        errors.append(contentsOf: pair.1)
    }
}

/// Protocol that all persistence mechanism scanners must conform to.
public protocol PersistenceScanner: Sendable {
    /// The persistence category this scanner covers.
    var category: PersistenceCategory { get }

    /// Human-readable name for this scanner.
    var displayName: String { get }

    /// Whether this scanner needs root privileges for full results.
    var requiresPrivilege: Bool { get }

    /// The filesystem paths this scanner inspects. Must describe what `scan()`
    /// actually reads — the UI, the exports and the privilege broker rely on it.
    var scanPaths: [String] { get }

    /// Perform the scan, returning both discovered items and any paths that
    /// could not be inspected.
    func scan() async throws -> ScanOutcome
}

// Default implementations
extension PersistenceScanner {
    public var displayName: String { category.displayName }

    /// Build a `ScanError` for a failure against a specific path, preserving the
    /// distinction between "denied" and "broken" so the UI can tell the user
    /// which categories need privileges.
    func scanError(_ error: Error, path: String? = nil) -> ScanError {
        if let failure = error as? SafeRead.Failure {
            return ScanError(
                category: category,
                path: path,
                message: failure.localizedDescription,
                isPermissionDenied: failure.isPermissionDenied
            )
        }
        let nsError = error as NSError
        let denied = (nsError.domain == NSPOSIXErrorDomain && nsError.code == Int(EACCES))
            || (nsError.domain == NSCocoaErrorDomain && nsError.code == NSFileReadNoPermissionError)
        return ScanError(
            category: category,
            path: path,
            message: error.localizedDescription,
            isPermissionDenied: denied
        )
    }

    /// Enumerate a directory, reporting an error when it exists but cannot be read.
    /// A directory that simply is not present is not an error.
    func entries(
        in directory: String,
        withExtension ext: String? = nil,
        includeHidden: Bool = false,
        includeDirectories: Bool = false
    ) -> ([String], [ScanError]) {
        guard PathUtilities.exists(directory) else { return ([], []) }
        do {
            let names = try FileManager.default.contentsOfDirectory(atPath: directory)
            var paths = names
                .filter { includeHidden || !$0.hasPrefix(".") }
                .map { (directory as NSString).appendingPathComponent($0) }
            if !includeDirectories {
                paths = paths.filter { !PathUtilities.isDirectory($0) }
            }
            if let ext {
                paths = paths.filter { ($0 as NSString).pathExtension == ext }
            }
            return (paths, [])
        } catch {
            return ([], [scanError(error, path: directory)])
        }
    }
}

/// Base helper for scanners that enumerate plist files in directories.
public struct DirectoryPlistScanner: Sendable {
    private let parser = PlistParser()

    public init() {}

    /// Scan directories for plist files and parse each one.
    ///
    /// `loadContext` is what `RunAtLoad` means in the enclosing domain — `.boot`
    /// for `LaunchDaemons`, `.login` for `LaunchAgents`. It used to be accepted
    /// and silently ignored, which meant no launch daemon could ever report a
    /// boot run context and the boot branch of the risk model was unreachable.
    public func scanPlists(
        in directories: [String],
        category: PersistenceCategory,
        owner: ItemOwner,
        loadContext: RunContext = .login
    ) -> ([PersistenceItem], [ScanError]) {
        var items: [PersistenceItem] = []
        var errors: [ScanError] = []
        let overrides = LaunchdStateResolver.shared

        for directory in directories {
            guard PathUtilities.exists(directory) else { continue }

            let plistPaths: [String]
            do {
                plistPaths = try FileManager.default.contentsOfDirectory(atPath: directory)
                    .filter { !$0.hasPrefix(".") && ($0 as NSString).pathExtension == "plist" }
                    .map { (directory as NSString).appendingPathComponent($0) }
            } catch {
                let nsError = error as NSError
                errors.append(ScanError(
                    category: category,
                    path: directory,
                    message: error.localizedDescription,
                    isPermissionDenied: nsError.code == NSFileReadNoPermissionError
                        || nsError.code == Int(EACCES)
                ))
                continue
            }

            for path in plistPaths {
                do {
                    let info = try parser.parseLaunchdPlist(at: path)
                    let timestamps = PathUtilities.timestamps(for: path)
                    let name = info.label ?? (path as NSString).lastPathComponent

                    let source = DirectoryPlistScanner.inferSource(
                        path: path, label: info.label
                    )

                    // The plist's `Disabled` key has not been authoritative since
                    // OS X 10.10 — launchd keeps enable/disable state in the
                    // override database. Trusting the key is exploitable: ship a
                    // plist marked disabled, then `launchctl enable` it.
                    let enabled = overrides.isEnabled(
                        label: info.label,
                        plistDisabledKey: info.disabled,
                        owner: owner
                    )

                    var item = PersistenceItem(
                        category: category,
                        name: name,
                        label: info.label,
                        configPath: path,
                        executablePath: info.resolvedExecutable,
                        arguments: info.programArguments,
                        isEnabled: enabled.isEnabled,
                        runContext: info.runContext(loadContext: loadContext),
                        owner: owner,
                        riskLevel: .medium, // will be refined by RiskAnalyzer
                        source: source,
                        timestamps: timestamps,
                        rawMetadata: info.rawDictionary
                    )
                    if let note = enabled.note {
                        item.riskReasons.append(note)
                    }
                    items.append(item)
                } catch {
                    let isPermission: Bool
                    if let failure = error as? SafeRead.Failure {
                        isPermission = failure.isPermissionDenied
                    } else {
                        let nsError = error as NSError
                        isPermission = nsError.domain == NSPOSIXErrorDomain
                            && nsError.code == Int(EACCES)
                    }
                    errors.append(ScanError(
                        category: category,
                        path: path,
                        message: error.localizedDescription,
                        isPermissionDenied: isPermission
                    ))
                }
            }
        }
        return (items, errors)
    }

    /// Determine whether a launchd plist is Apple-provided based on its
    /// filesystem path.
    ///
    /// Only the path is considered. A label can claim `com.apple.anything` —
    /// it is written by whoever wrote the file — so it must never be used to
    /// conclude "Apple". For plists outside Apple-owned directories the source
    /// stays `.unknown` and the signing verifier provides the definitive answer.
    static func inferSource(path: String, label: String?) -> ItemSource {
        PathUtilities.isAppleOwnedPath(path) ? .apple : .unknown
    }
}

/// Base helper for scanners that enumerate bundles in directories.
public struct DirectoryBundleScanner: Sendable {

    public init() {}

    /// Scan directories for bundles with a given extension.
    public func scanBundles(
        in directories: [String],
        bundleExtension: String,
        category: PersistenceCategory,
        owner: ItemOwner,
        runContext: RunContext = .onDemand
    ) -> ([PersistenceItem], [ScanError]) {
        scanBundles(
            in: directories,
            bundleExtensions: [bundleExtension],
            category: category,
            owner: owner,
            runContext: runContext
        )
    }

    /// Scan directories for bundles matching any of the given extensions.
    public func scanBundles(
        in directories: [String],
        bundleExtensions: [String],
        category: PersistenceCategory,
        owner: ItemOwner,
        runContext: RunContext = .onDemand
    ) -> ([PersistenceItem], [ScanError]) {
        var items: [PersistenceItem] = []
        var errors: [ScanError] = []

        for directory in directories {
            guard PathUtilities.exists(directory) else { continue }

            let bundlePaths: [String]
            do {
                let wanted = Set(bundleExtensions)
                bundlePaths = try FileManager.default.contentsOfDirectory(atPath: directory)
                    .filter { wanted.contains(($0 as NSString).pathExtension) }
                    .map { (directory as NSString).appendingPathComponent($0) }
            } catch {
                let nsError = error as NSError
                errors.append(ScanError(
                    category: category,
                    path: directory,
                    message: error.localizedDescription,
                    isPermissionDenied: nsError.code == NSFileReadNoPermissionError
                        || nsError.code == Int(EACCES)
                ))
                continue
            }

            for path in bundlePaths {
                let name = ((path as NSString).lastPathComponent as NSString).deletingPathExtension
                let infoPlistPath = (path as NSString).appendingPathComponent("Contents/Info.plist")
                let timestamps = PathUtilities.timestamps(for: path)

                var label: String?
                var executablePath: String?
                var metadata: [String: PlistValue] = [:]

                if PathUtilities.exists(infoPlistPath) {
                    do {
                        let dict = try PlistParser().parse(at: infoPlistPath)
                        label = dict["CFBundleIdentifier"] as? String
                        if let execName = dict["CFBundleExecutable"] as? String {
                            executablePath = (path as NSString)
                                .appendingPathComponent("Contents/MacOS/\(execName)")
                        }
                        metadata = PlistParser().toMetadata(dict)
                    } catch {
                        let failure = error as? SafeRead.Failure
                        errors.append(ScanError(
                            category: category,
                            path: infoPlistPath,
                            message: error.localizedDescription,
                            isPermissionDenied: failure?.isPermissionDenied ?? false
                        ))
                    }
                }

                // Path only. A bundle identifier read from the bundle's own
                // Info.plist is attacker-chosen: an unsigned `.qlgenerator`
                // claiming `com.apple.quicklook.Video` used to be classified as
                // Apple and hidden from the default view.
                let source: ItemSource = PathUtilities.isAppleOwnedPath(path) ? .apple : .unknown

                items.append(PersistenceItem(
                    category: category,
                    name: name,
                    label: label,
                    configPath: path,
                    executablePath: executablePath,
                    isEnabled: true,
                    runContext: runContext,
                    owner: owner,
                    source: source,
                    timestamps: timestamps,
                    rawMetadata: metadata
                ))
            }
        }

        return (items, errors)
    }
}

/// A scanner that is entirely described by "look for bundles with extension X in
/// these directories".
///
/// Five scanners (QuickLook, Spotlight, ScreenSaver, ScriptingAddition, Widget)
/// were byte-identical apart from four tokens, each repeating its directory list
/// twice — once in `scanPaths` and once in `scan()`. That duplication is how the
/// two lists drifted apart and how `/System/Library` paths went missing.
public protocol BundleDirectoryScanner: PersistenceScanner {
    /// Extensions that identify a plugin bundle for this category.
    var bundleExtensions: [String] { get }
    /// System-wide directories, scanned as `.system`.
    var systemDirectories: [String] { get }
    /// Per-user directory suffixes relative to a home directory, e.g.
    /// `Library/QuickLook`.
    var userDirectorySuffixes: [String] { get }
    /// Run context to record for discovered items.
    var bundleRunContext: RunContext { get }
}

extension BundleDirectoryScanner {
    public var bundleRunContext: RunContext { .onDemand }

    /// Single source of truth for the paths this scanner reads.
    public var scanPaths: [String] {
        var paths = systemDirectories
        for (_, home) in PathUtilities.scannableHomeDirectories() {
            for suffix in userDirectorySuffixes {
                paths.append((home as NSString).appendingPathComponent(suffix))
            }
        }
        return paths
    }

    public var requiresPrivilege: Bool { false }

    public func scan() async throws -> ScanOutcome {
        try await defaultBundleScan()
    }

    /// The shared implementation, also callable from a conformer that wants to
    /// post-process the result.
    func defaultBundleScan() async throws -> ScanOutcome {
        let helper = DirectoryBundleScanner()
        var outcome = ScanOutcome()

        outcome.merge(helper.scanBundles(
            in: systemDirectories,
            bundleExtensions: bundleExtensions,
            category: category,
            owner: .system,
            runContext: bundleRunContext
        ))

        for (user, home) in PathUtilities.scannableHomeDirectories() {
            let directories = userDirectorySuffixes.map {
                (home as NSString).appendingPathComponent($0)
            }
            outcome.merge(helper.scanBundles(
                in: directories,
                bundleExtensions: bundleExtensions,
                category: category,
                owner: .user(user),
                runContext: bundleRunContext
            ))
        }

        return outcome
    }
}
