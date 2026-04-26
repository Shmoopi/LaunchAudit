import Foundation

public struct ProfileScanner: PersistenceScanner {
    public let category = PersistenceCategory.configurationProfiles
    public let requiresPrivilege = true

    public var scanPaths: [String] {
        ["/var/db/ConfigurationProfiles"]
    }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        // Single invocation — request XML, then route to the appropriate
        // parser based on the actual output format. The previous code ran
        // `profiles list` twice (once XML, once text fallback), doubling
        // the cost on machines where XML wasn't honoured. Skip /bin/sh —
        // direct exec is faster.
        guard let output = await ProcessRunner.shared.tryRun(
            "/usr/bin/profiles", arguments: ["list", "-output", "stdout-xml"]
        ) else {
            return []
        }

        let trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return [] }

        // Route on the first non-whitespace bytes — `profiles` falls back
        // to text on systems where the XML format isn't honoured.
        if trimmed.hasPrefix("<?xml") || trimmed.hasPrefix("<plist") {
            return parseProfilesXML(output)
        }
        return parseProfilesText(output)
    }

    private func parseProfilesXML(_ xml: String) -> [PersistenceItem] {
        var items: [PersistenceItem] = []

        guard let data = xml.data(using: .utf8),
              let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] else {
            return items
        }

        // Navigate the profiles plist structure
        if let computeLevel = plist["_computerlevel"] as? [[String: Any]] {
            for profile in computeLevel {
                if let item = profileToItem(profile, owner: .system) {
                    items.append(item)
                }
            }
        }

        return items
    }

    private func profileToItem(_ dict: [String: Any], owner: ItemOwner) -> PersistenceItem? {
        let name = dict["ProfileDisplayName"] as? String
            ?? dict["ProfileIdentifier"] as? String
            ?? "Unknown Profile"
        let identifier = dict["ProfileIdentifier"] as? String
        let organization = dict["ProfileOrganization"] as? String

        return PersistenceItem(
            category: category,
            name: name,
            label: identifier,
            isEnabled: true,
            runContext: .boot,
            owner: owner,
            source: organization.map { .thirdParty($0) } ?? .unknown,
            rawMetadata: PlistParser().toMetadata(dict)
        )
    }

    private func parseProfilesText(_ output: String) -> [PersistenceItem] {
        var items: [PersistenceItem] = []
        var currentName: String?
        var currentID: String?

        for line in output.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("attribute:") && trimmed.contains("profileIdentifier") {
                currentID = trimmed.components(separatedBy: ":").last?.trimmingCharacters(in: .whitespaces)
            } else if trimmed.hasPrefix("attribute:") && trimmed.contains("profileDisplayName") {
                currentName = trimmed.components(separatedBy: ":").last?.trimmingCharacters(in: .whitespaces)
            } else if trimmed.isEmpty, let name = currentName ?? currentID {
                items.append(PersistenceItem(
                    category: category,
                    name: name,
                    label: currentID,
                    isEnabled: true,
                    runContext: .boot,
                    owner: .system
                ))
                currentName = nil
                currentID = nil
            }
        }

        // Don't forget the last item
        if let name = currentName ?? currentID {
            items.append(PersistenceItem(
                category: category,
                name: name,
                label: currentID,
                isEnabled: true,
                runContext: .boot,
                owner: .system
            ))
        }

        return items
    }
}
