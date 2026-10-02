import Foundation

public struct SystemExtensionScanner: PersistenceScanner {
    public let category = PersistenceCategory.systemExtensions
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        ["/Library/SystemExtensions"]
    }

    public init() {}

    public func scan() async throws -> ScanOutcome {
        var outcome = ScanOutcome()

        guard let output = await ProcessRunner.shared.tryRun(
            "/usr/bin/systemextensionsctl", arguments: ["list"], timeout: 10
        ) else {
            outcome.errors.append(ScanError(
                category: category,
                message: "systemextensionsctl list produced no output",
                isPermissionDenied: false
            ))
            return outcome
        }

        outcome.items = parseSystemExtensionsList(output)
        return outcome
    }

    /// Parse `systemextensionsctl list`.
    ///
    /// Real output is tab-separated:
    /// ```
    /// enabled	active	teamID	bundleID (version)	name	[state]
    /// *	*	VBG97UB4TA	com.objective-see.lulu.extension (4.5.1/4.5.1)	LuLu	[activated enabled]
    /// ```
    /// The previous parser split on whitespace, discarded the name column and then
    /// derived a name from the last dot-component of the bundle ID — so LuLu was
    /// displayed as "extension" and ProtonVPN as "WireGuard-Extension".
    func parseSystemExtensionsList(_ output: String) -> [PersistenceItem] {
        var items: [PersistenceItem] = []

        for line in output.components(separatedBy: "\n") {
            guard !line.trimmingCharacters(in: .whitespaces).isEmpty else { continue }
            // Skip the count line, category headers and the column header.
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.hasPrefix("---"),
                  !trimmed.hasSuffix("extension(s)"),
                  !trimmed.hasPrefix("enabled") else { continue }

            let fields = line.components(separatedBy: "\t").map {
                $0.trimmingCharacters(in: .whitespaces)
            }
            // enabled, active, teamID, "bundleID (version)", name, [state]
            guard fields.count >= 4 else { continue }

            let enabledFlag = fields[0] == "*"
            let activeFlag = fields[1] == "*"
            let teamID = fields[2].isEmpty ? nil : fields[2]

            // "bundleID (version)"
            let identifierField = fields[3]
            let bundleID = identifierField
                .components(separatedBy: " ")
                .first?
                .trimmingCharacters(in: .whitespaces) ?? identifierField
            guard !bundleID.isEmpty, bundleID.contains(".") else { continue }

            var version: String?
            if let open = identifierField.firstIndex(of: "("),
               let close = identifierField.lastIndex(of: ")"), open < close {
                version = String(identifierField[identifierField.index(after: open)..<close])
            }

            let displayName = fields.count > 4 && !fields[4].isEmpty ? fields[4] : bundleID
            let state = fields.count > 5
                ? fields[5].trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
                : nil

            // Resolve the on-disk bundle so the signature actually gets verified.
            // Third-party system extensions are among the highest-privilege code
            // on a Mac; previously none of them was checked at all because no
            // executablePath was ever set.
            let bundle = Self.locateBundle(bundleID: bundleID)

            var metadata: [String: PlistValue] = [
                "Source": .string("systemextensionsctl"),
                "Active": .bool(activeFlag),
            ]
            if let version { metadata["Version"] = .string(version) }
            if let state { metadata["State"] = .string(state) }
            if let teamID { metadata["TeamID"] = .string(teamID) }
            if let bundle { metadata["BundlePath"] = .string(bundle.bundlePath) }

            items.append(PersistenceItem(
                category: category,
                name: displayName,
                label: bundleID,
                configPath: bundle?.bundlePath,
                executablePath: bundle?.executablePath,
                isEnabled: enabledFlag,
                runContext: .boot,
                owner: .system,
                source: teamID.map(ItemSource.thirdParty) ?? .unknown,
                timestamps: bundle.map { PathUtilities.timestamps(for: $0.bundlePath) }
                    ?? ItemTimestamps(),
                rawMetadata: metadata
            ))
        }

        return items
    }

    /// Find the staged bundle for a system extension.
    /// Layout: /Library/SystemExtensions/<UUID>/<bundleID>.systemextension
    private static func locateBundle(
        bundleID: String
    ) -> (bundlePath: String, executablePath: String?)? {
        let root = "/Library/SystemExtensions"
        let wanted = "\(bundleID).systemextension"

        for container in PathUtilities.listDirectories(in: root) {
            let candidate = (container as NSString).appendingPathComponent(wanted)
            guard PathUtilities.exists(candidate) else { continue }

            var executablePath: String?
            let infoPlist = (candidate as NSString)
                .appendingPathComponent("Contents/Info.plist")
            if let dict = try? PlistParser().parse(at: infoPlist),
               let execName = dict["CFBundleExecutable"] as? String {
                executablePath = (candidate as NSString)
                    .appendingPathComponent("Contents/MacOS/\(execName)")
            }
            return (candidate, executablePath)
        }
        return nil
    }
}
