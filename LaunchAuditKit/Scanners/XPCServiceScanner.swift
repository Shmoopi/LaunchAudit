import Foundation

public struct XPCServiceScanner: PersistenceScanner {
    public let category = PersistenceCategory.xpcServices
    public let requiresPrivilege = true

    public var scanPaths: [String] { [] }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        var items: [PersistenceItem] = []

        // Check for standalone XPC services in common locations
        let xpcDirs = [
            "/Library/Apple/System/Library/XPCServices",
            "/Library/Developer/XPCServices"
        ]

        let scanner = DirectoryBundleScanner()
        for dir in xpcDirs {
            guard PathUtilities.exists(dir) else { continue }
            let (found, _) = scanner.scanBundles(
                in: [dir],
                bundleExtension: "xpc",
                category: category,
                owner: .system
            )
            items.append(contentsOf: found)
        }

        return items
    }
}
