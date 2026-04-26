import Foundation

public struct AuthPluginScanner: PersistenceScanner {
    public let category = PersistenceCategory.authorizationPlugins
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        ["/Library/Security/SecurityAgentPlugins"]
    }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        let scanner = DirectoryBundleScanner()
        let (items, _) = scanner.scanBundles(
            in: ["/Library/Security/SecurityAgentPlugins"],
            bundleExtension: "bundle",
            category: category,
            owner: .system
        )

        // Also check which plugins are referenced in the authorization database
        var referencedPlugins = Set<String>()
        if let output = await ProcessRunner.shared.tryRun(
            "/usr/bin/security",
            arguments: ["authorizationdb", "read", "system.login.console"]
        ) {
            // Parse for plugin references
            for line in output.components(separatedBy: "\n") {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.contains("privileged") || trimmed.contains("plugin") {
                    // Extract plugin names from the plist-style output
                    if let range = trimmed.range(of: "<string>") {
                        let start = range.upperBound
                        if let endRange = trimmed.range(of: "</string>", range: start..<trimmed.endIndex) {
                            let plugin = String(trimmed[start..<endRange.lowerBound])
                            referencedPlugins.insert(plugin)
                        }
                    }
                }
            }
        }

        return items.map { item in
            var modified = item
            let isReferenced = referencedPlugins.contains(item.name)
            if isReferenced {
                modified = PersistenceItem(
                    id: item.id, category: item.category, name: item.name,
                    label: item.label, configPath: item.configPath,
                    executablePath: item.executablePath, arguments: item.arguments,
                    isEnabled: item.isEnabled, runContext: .login, owner: item.owner,
                    signingInfo: item.signingInfo, riskLevel: item.riskLevel,
                    riskReasons: item.riskReasons, source: item.source,
                    timestamps: item.timestamps,
                    rawMetadata: item.rawMetadata.merging(["ReferencedInAuthDB": .bool(true)]) { _, n in n }
                )
            }
            return modified
        }
    }
}
