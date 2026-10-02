import Foundation

// Plugin categories that are fully described by "bundles with extension X in
// these directories".
//
// These were five separate files, byte-identical apart from four tokens, each
// listing its directories twice — once in `scanPaths` and once in `scan()`. That
// duplication is why the two lists drifted. `BundleDirectoryScanner` now derives
// `scanPaths` from the same declarations `scan()` uses, so they cannot disagree.
//
// Scope note: only the writable `/Library` and per-user locations are scanned.
// The `/System/Library` equivalents sit on the sealed system volume, where SIP
// prevents modification, so enumerating them would add hundreds of unactionable
// Apple rows and scan time for no detection value.

public struct QuickLookScanner: BundleDirectoryScanner {
    public let category = PersistenceCategory.quickLookGenerators
    public let bundleExtensions = ["qlgenerator"]
    public let systemDirectories = ["/Library/QuickLook"]
    public let userDirectorySuffixes = ["Library/QuickLook"]
    public init() {}
}

public struct SpotlightScanner: BundleDirectoryScanner {
    public let category = PersistenceCategory.spotlightImporters
    public let bundleExtensions = ["mdimporter"]
    public let systemDirectories = ["/Library/Spotlight"]
    public let userDirectorySuffixes = ["Library/Spotlight"]
    public init() {}
}

public struct ScreenSaverScanner: BundleDirectoryScanner {
    public let category = PersistenceCategory.screenSavers
    public let bundleExtensions = ["saver"]
    public let systemDirectories = ["/Library/Screen Savers"]
    public let userDirectorySuffixes = ["Library/Screen Savers"]
    public init() {}
}

public struct ScriptingAdditionScanner: BundleDirectoryScanner {
    public let category = PersistenceCategory.scriptingAdditions
    public let bundleExtensions = ["osax"]
    public let systemDirectories = ["/Library/ScriptingAdditions"]
    public let userDirectorySuffixes = ["Library/ScriptingAdditions"]
    public init() {}
}

/// Dashboard widgets.
///
/// Dashboard was removed in macOS 10.15 and this project targets macOS 14+, so
/// these directories do not exist on any supported system. The scanner is kept as
/// a **legacy tripwire**: it costs one `exists` check, stays silent when absent,
/// and anything it does find was placed there by a migration or an attacker
/// rather than by the OS — which is why a hit is escalated rather than ignored.
public struct WidgetScanner: BundleDirectoryScanner {
    public let category = PersistenceCategory.widgets
    public let bundleExtensions = ["wdgt"]
    public let systemDirectories = ["/Library/Widgets"]
    public let userDirectorySuffixes = ["Library/Widgets"]
    public init() {}

    public func scan() async throws -> ScanOutcome {
        var outcome = try await defaultBundleScan()
        for index in outcome.items.indices {
            outcome.items[index].riskReasons.append(
                "Dashboard was removed in macOS 10.15 — this location should not exist"
            )
            outcome.items[index].riskLevel = .high
        }
        return outcome
    }
}

// `defaultBundleScan()` lives with the protocol in PersistenceScanner.swift.
