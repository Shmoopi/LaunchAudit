import Foundation

public struct AutomatorScanner: PersistenceScanner {
    public let category = PersistenceCategory.automatorWorkflows
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        [PathUtilities.expandTilde("~/Library/Services")]
    }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        var items: [PersistenceItem] = []

        let servicesDir = PathUtilities.expandTilde("~/Library/Services")
        guard PathUtilities.exists(servicesDir) else { return items }

        let workflows = PathUtilities.listBundles(in: servicesDir, withExtension: "workflow")
        for workflow in workflows {
            let name = ((workflow as NSString).lastPathComponent as NSString).deletingPathExtension
            let timestamps = PathUtilities.timestamps(for: workflow)

            items.append(PersistenceItem(
                category: category,
                name: name,
                configPath: workflow,
                isEnabled: true,
                runContext: .onDemand,
                owner: .user(PathUtilities.currentUser),
                timestamps: timestamps,
                rawMetadata: ["Type": .string("Quick Action")]
            ))
        }

        return items
    }
}
