import Foundation

public struct PrivilegedHelperScanner: PersistenceScanner {
    public let category = PersistenceCategory.privilegedHelperTools
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        ["/Library/PrivilegedHelperTools"]
    }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        var items: [PersistenceItem] = []
        let directory = "/Library/PrivilegedHelperTools"

        guard PathUtilities.exists(directory) else { return items }

        let files = PathUtilities.listFiles(in: directory)
        for file in files {
            let name = (file as NSString).lastPathComponent
            let timestamps = PathUtilities.timestamps(for: file)

            items.append(PersistenceItem(
                category: category,
                name: name,
                label: name, // typically a reverse-DNS identifier
                configPath: file,
                executablePath: file,
                isEnabled: true,
                runContext: .onDemand,
                owner: .system,
                timestamps: timestamps,
                rawMetadata: ["Directory": .string(directory)]
            ))
        }

        return items
    }
}
