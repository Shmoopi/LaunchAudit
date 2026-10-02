import Foundation

public struct AudioPluginScanner: BundleDirectoryScanner {
    public let category = PersistenceCategory.audioPlugins

    /// `.plugin` and `.driver` are both loaded from the HAL directory; `Components`
    /// holds Audio Units, which are loaded into every audio host process and were
    /// previously not scanned at all.
    public let bundleExtensions = ["plugin", "driver", "component"]

    public let systemDirectories = [
        "/Library/Audio/Plug-Ins/HAL",
        "/Library/Audio/Plug-Ins/Components",
    ]

    public let userDirectorySuffixes = [
        "Library/Audio/Plug-Ins/HAL",
        "Library/Audio/Plug-Ins/Components",
    ]

    public init() {}
}
