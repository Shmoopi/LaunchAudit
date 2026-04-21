import Foundation

/// Protocol that all persistence mechanism scanners must conform to.
public protocol PersistenceScanner: Sendable {
    /// The persistence category this scanner covers.
    var category: PersistenceCategory { get }

    /// Human-readable name for this scanner.
    var displayName: String { get }

    /// Whether this scanner needs root privileges for full results.
    var requiresPrivilege: Bool { get }

    /// The filesystem paths this scanner inspects.
    var scanPaths: [String] { get }

    /// Perform the scan and return discovered persistence items.
    func scan() async throws -> [PersistenceItem]
}

// Default implementations
extension PersistenceScanner {
    public var displayName: String { category.displayName }
}

/// Base helper for scanners that enumerate plist files in directories.
public struct DirectoryPlistScanner: Sendable {
    private let parser = PlistParser()

    public init() {}

    /// Scan directories for plist files and parse each one.
    public func scanPlists(
        in directories: [String],
        category: PersistenceCategory,
        owner: ItemOwner,
        runContext: RunContext = .login
    ) -> ([PersistenceItem], [ScanError]) {
        var items: [PersistenceItem] = []
        var errors: [ScanError] = []

        for directory in directories {
            let plistPaths = PathUtilities.listFiles(in: directory, withExtension: "plist")
            for path in plistPaths {
                do {
                    let info = try parser.parseLaunchdPlist(at: path)
                    let timestamps = PathUtilities.timestamps(for: path)
                    let name = info.label ?? (path as NSString).lastPathComponent

                    let source = DirectoryPlistScanner.inferSource(
                        path: path, label: info.label
                    )

                    let item = PersistenceItem(
                        category: category,
                        name: name,
                        label: info.label,
                        configPath: path,
                        executablePath: info.resolvedExecutable,
                        arguments: info.programArguments,
                        isEnabled: !info.disabled,
                        runContext: info.runContext,
                        owner: owner,
                        riskLevel: .medium, // will be refined by RiskAnalyzer
                        source: source,
                        timestamps: timestamps,
                        rawMetadata: info.rawDictionary
                    )
                    items.append(item)
                } catch {
                    let isPermission = (error as NSError).domain == NSPOSIXErrorDomain
                        && (error as NSError).code == 13
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
    /// filesystem path and label.  Everything on the sealed system volume
    /// (`/System/Library/`) is Apple by definition.  For items in `/Library/`,
    /// we leave source as `.unknown` so the signing verifier provides the
    /// definitive answer — label prefixes alone can be spoofed.
    static func inferSource(path: String, label: String?) -> ItemSource {
        // Anything under /System/Library is Apple (sealed system volume)
        if path.hasPrefix("/System/Library/") {
            return .apple
        }

        // For items outside the sealed system volume, only trust the label
        // heuristic when the plist is in a SIP-protected location that
        // requires root to modify.  /Library/LaunchDaemons and
        // /Library/LaunchAgents are root-owned but NOT SIP-protected,
        // so we let signing verification determine the real source.
        return .unknown
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
        owner: ItemOwner
    ) -> ([PersistenceItem], [ScanError]) {
        var items: [PersistenceItem] = []
        let errors: [ScanError] = []

        for directory in directories {
            guard PathUtilities.exists(directory) else { continue }
            let bundlePaths = PathUtilities.listBundles(in: directory, withExtension: bundleExtension)

            for path in bundlePaths {
                let name = ((path as NSString).lastPathComponent as NSString).deletingPathExtension
                let infoPlistPath = (path as NSString).appendingPathComponent("Contents/Info.plist")
                let timestamps = PathUtilities.timestamps(for: path)

                var label: String?
                var executablePath: String?
                var metadata: [String: PlistValue] = [:]

                if PathUtilities.exists(infoPlistPath),
                   let dict = try? PlistParser().parse(at: infoPlistPath) {
                    label = dict["CFBundleIdentifier"] as? String
                    if let execName = dict["CFBundleExecutable"] as? String {
                        executablePath = (path as NSString)
                            .appendingPathComponent("Contents/MacOS/\(execName)")
                    }
                    metadata = PlistParser().toMetadata(dict)
                }

                let source: ItemSource = path.hasPrefix("/System/Library/")
                    || (label?.hasPrefix("com.apple.") ?? false)
                    ? .apple : .unknown

                items.append(PersistenceItem(
                    category: category,
                    name: name,
                    label: label,
                    configPath: path,
                    executablePath: executablePath,
                    isEnabled: true,
                    runContext: .onDemand,
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
