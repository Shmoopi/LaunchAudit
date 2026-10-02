import Foundation

public struct PrinterPluginScanner: PersistenceScanner {
    public let category = PersistenceCategory.printerPlugins
    public let requiresPrivilege = false

    /// `/usr/libexec/cups/filter` is the canonical CUPS filter location and is what
    /// the category description promises. It was missing entirely.
    private let filterDirectories = [
        "/usr/libexec/cups/filter",
        "/usr/libexec/cups/backend",
        "/Library/Printers/PPDs/Contents/Resources",
    ]

    private let vendorRoot = "/Library/Printers"

    public var scanPaths: [String] { [vendorRoot] + filterDirectories }

    public init() {}

    public func scan() async throws -> ScanOutcome {
        var outcome = ScanOutcome()

        // Vendor driver bundles.
        //
        // The previous implementation listed the *top level* of /Library/Printers
        // and reported each entry as a plugin — which on a normal machine means
        // `Icons` and `PPDs` were reported as printer plugins while the actual
        // driver and filter binaries nested under `Canon/` and `EPSON/` were never
        // reached. Descend one level and look for real bundles.
        let (vendors, vendorErrors) = entries(
            in: vendorRoot, includeDirectories: true
        )
        outcome.errors += vendorErrors

        let helper = DirectoryBundleScanner()
        let bundleExtensions = ["plugin", "bundle", "driver", "app"]

        for vendor in vendors where PathUtilities.isDirectory(vendor) {
            let name = (vendor as NSString).lastPathComponent
            // Resource directories, not plugin containers.
            guard !["Icons", "PPDs", "PPD Plugins"].contains(name) else { continue }

            // A vendor directory may itself be a bundle, or contain them.
            if bundleExtensions.contains((vendor as NSString).pathExtension) {
                outcome.merge(helper.scanBundles(
                    in: [vendorRoot],
                    bundleExtensions: bundleExtensions,
                    category: category,
                    owner: .system,
                    runContext: .onDemand
                ))
                continue
            }

            outcome.merge(helper.scanBundles(
                in: [vendor, (vendor as NSString).appendingPathComponent("Contents/Plugins")],
                bundleExtensions: bundleExtensions,
                category: category,
                owner: .system,
                runContext: .onDemand
            ))
        }

        // CUPS filters and backends are plain executables, not bundles.
        for directory in filterDirectories {
            let (files, errors) = entries(in: directory)
            outcome.errors += errors
            for file in files {
                // Only executables are filters.
                guard FileManager.default.isExecutableFile(atPath: file) else { continue }
                outcome.items.append(PersistenceItem(
                    category: category,
                    name: (file as NSString).lastPathComponent,
                    configPath: file,
                    executablePath: file,
                    isEnabled: true,
                    runContext: .onDemand,
                    owner: .system,
                    source: PathUtilities.isAppleOwnedPath(file) ? .apple : .unknown,
                    timestamps: PathUtilities.timestamps(for: file),
                    rawMetadata: [
                        "Type": .string("CUPS filter"),
                        "Directory": .string(directory),
                    ]
                ))
            }
        }

        return outcome
    }
}
