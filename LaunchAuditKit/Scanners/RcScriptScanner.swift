import Foundation

public struct RcScriptScanner: PersistenceScanner {
    public let category = PersistenceCategory.rcScripts
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        // rc.common is a stock Apple helper-function library (not a persistence vector)
        // Only rc.local and rc.shutdown.local indicate attacker-created persistence
        ["/etc/rc.local", "/etc/rc.shutdown.local"]
    }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        var items: [PersistenceItem] = []

        for path in scanPaths {
            guard PathUtilities.exists(path) else { continue }
            let name = (path as NSString).lastPathComponent
            let timestamps = PathUtilities.timestamps(for: path)

            var riskLevel: RiskLevel = .medium
            var riskReasons = ["Legacy rc script exists: \(name)"]

            // rc.local and rc.shutdown.local are particularly noteworthy
            if name == "rc.local" || name == "rc.shutdown.local" {
                riskLevel = .high
                riskReasons.append("rc.local scripts are a known persistence mechanism")
            }

            items.append(PersistenceItem(
                category: category,
                name: name,
                configPath: path,
                executablePath: path,
                isEnabled: true,
                runContext: name.contains("shutdown") ? .manual : .boot,
                owner: .system,
                riskLevel: riskLevel,
                riskReasons: riskReasons,
                timestamps: timestamps,
                rawMetadata: ["Type": .string("rc script")]
            ))
        }

        return items
    }
}
