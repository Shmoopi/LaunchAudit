import Foundation

public struct NetworkScriptScanner: PersistenceScanner {
    public let category = PersistenceCategory.networkScripts
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        ["/etc/ppp"]
    }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        var items: [PersistenceItem] = []

        let scripts = ["ip-up", "ip-down", "ipv6-up", "ipv6-down"]
        for script in scripts {
            let path = "/etc/ppp/\(script)"
            guard PathUtilities.exists(path) else { continue }
            let timestamps = PathUtilities.timestamps(for: path)

            items.append(PersistenceItem(
                category: category,
                name: script,
                configPath: path,
                executablePath: path,
                isEnabled: true,
                runContext: .triggered,
                owner: .system,
                timestamps: timestamps,
                rawMetadata: [
                    "Type": .string("PPP script"),
                    "Trigger": .string(script.contains("up") ? "network-up" : "network-down")
                ]
            ))
        }

        return items
    }
}
