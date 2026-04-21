import Foundation

public struct SystemExtensionScanner: PersistenceScanner {
    public let category = PersistenceCategory.systemExtensions
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        ["/Library/SystemExtensions"]
    }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        var items: [PersistenceItem] = []

        // Query systemextensionsctl
        if let output = await ProcessRunner.shared.tryShell("systemextensionsctl list 2>/dev/null") {
            items.append(contentsOf: parseSystemExtensionsList(output))
        }

        return items
    }

    private func parseSystemExtensionsList(_ output: String) -> [PersistenceItem] {
        var items: [PersistenceItem] = []

        for line in output.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty,
                  !trimmed.hasPrefix("---"),
                  !trimmed.hasPrefix("System Extensions") else { continue }

            // Lines typically look like:
            // --- com.apple.system_extension.network_extension
            // enabled	active	teamID	bundleID (version)	name	[state]
            // * * TEAMID bundleID (1.0/1) identifer [activated ...]

            let parts = trimmed.components(separatedBy: .whitespaces).filter { !$0.isEmpty }
            guard parts.count >= 4 else { continue }

            // Find the bundle identifier (contains dots, not a flag character)
            var teamID: String?
            var bundleID: String?
            var extensionName: String?
            var state: String?

            for (i, part) in parts.enumerated() {
                if part.count == 10 && part.allSatisfy({ $0.isLetter || $0.isNumber }) && teamID == nil && bundleID == nil {
                    teamID = part
                } else if part.contains(".") && !part.hasPrefix("(") && !part.hasPrefix("/") && bundleID == nil {
                    bundleID = part
                } else if part.hasPrefix("[") {
                    state = parts[i...].joined(separator: " ")
                        .replacingOccurrences(of: "[", with: "")
                        .replacingOccurrences(of: "]", with: "")
                    break
                }
            }

            guard let id = bundleID else { continue }
            extensionName = id.components(separatedBy: ".").last ?? id

            let isEnabled = trimmed.contains("enabled") || trimmed.contains("activated")
                || trimmed.hasPrefix("*")

            var metadata: [String: PlistValue] = [
                "RawLine": .string(trimmed),
                "Source": .string("systemextensionsctl")
            ]
            if let s = state { metadata["State"] = .string(s) }
            if let t = teamID { metadata["TeamID"] = .string(t) }

            items.append(PersistenceItem(
                category: category,
                name: extensionName ?? id,
                label: id,
                isEnabled: isEnabled,
                runContext: .boot,
                owner: .system,
                source: teamID != nil ? .thirdParty(teamID!) : .unknown,
                rawMetadata: metadata
            ))
        }

        return items
    }
}
