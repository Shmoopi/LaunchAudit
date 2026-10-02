import Foundation

public struct DirectoryServicesScanner: BundleDirectoryScanner {
    public let category = PersistenceCategory.directoryServicesPlugins
    public let bundleExtensions = ["dsplug"]
    public let systemDirectories = ["/Library/DirectoryServices/PlugIns"]
    public let userDirectorySuffixes: [String] = []
    public init() {}
}
