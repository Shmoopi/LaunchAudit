import Foundation

public struct BTMScanner: PersistenceScanner {
    public let category = PersistenceCategory.backgroundTaskManagement
    public let requiresPrivilege = true

    public var scanPaths: [String] {
        ["/private/var/db/com.apple.backgroundtaskmanagement"]
    }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        guard let output = await ProcessRunner.shared.tryShell("sfltool dumpbtm 2>/dev/null") else {
            return []
        }
        return parseBTMOutput(output)
    }

    // MARK: - Parsing

    /// Parse the full sfltool dumpbtm output into items.
    func parseBTMOutput(_ output: String) -> [PersistenceItem] {
        var items: [PersistenceItem] = []
        var seenUUIDs = Set<String>()

        // Split into per-UID sections
        let sections = output.components(separatedBy: "========================")
        // Sections alternate: header, content, header, content...
        for section in sections {
            let trimmed = section.trimmingCharacters(in: .whitespacesAndNewlines)
            guard trimmed.contains("Items:") else { continue }

            // Determine UID context from the preceding header
            let uid = extractUID(from: trimmed)

            // Split section into individual item blocks on " #N:"
            let itemBlocks = splitItemBlocks(trimmed)

            for block in itemBlocks {
                guard let parsed = parseItemBlock(block, uid: uid) else { continue }
                // Deduplicate across UID sections by UUID
                guard seenUUIDs.insert(parsed.uuid).inserted else { continue }
                items.append(parsed.item)
            }
        }

        return items
    }

    /// Split a section's Items area into individual numbered blocks.
    private func splitItemBlocks(_ section: String) -> [String] {
        // Find "Items:" marker
        guard let itemsRange = section.range(of: "Items:") else { return [] }
        let itemsBody = String(section[itemsRange.upperBound...])

        // Split on the " #N:" pattern (each item starts with " #<number>:")
        var blocks: [String] = []
        let pattern = #"\n\s*#\d+:"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        let nsString = itemsBody as NSString
        let matches = regex.matches(in: itemsBody, range: NSRange(location: 0, length: nsString.length))

        for (i, match) in matches.enumerated() {
            let start = match.range.location
            let end = i + 1 < matches.count
                ? matches[i + 1].range.location
                : nsString.length
            let block = nsString.substring(with: NSRange(location: start, length: end - start))
            blocks.append(block)
        }

        return blocks
    }

    private struct ParsedItem {
        let uuid: String
        let item: PersistenceItem
    }

    /// Parse a single BTM item block.
    private func parseItemBlock(_ block: String, uid: Int?) -> ParsedItem? {
        var fields: [String: String] = [:]

        for line in block.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard let colonRange = trimmed.range(of: ": ") else { continue }
            let key = String(trimmed[..<colonRange.lowerBound])
                .trimmingCharacters(in: .whitespaces)
            let value = String(trimmed[colonRange.upperBound...])
                .trimmingCharacters(in: .whitespaces)
            if !value.isEmpty && value != "(null)" {
                fields[key] = value
            }
        }

        // Also extract Embedded Item Identifiers and Assoc. Bundle IDs
        var embeddedItems: [String] = []
        var assocBundleIDs: [String] = []
        for line in block.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("#") && trimmed.contains(": ") && !trimmed.hasPrefix("# ") {
                // "#1: identifier" under Embedded Item Identifiers
                if let value = trimmed.components(separatedBy: ": ").last {
                    embeddedItems.append(value)
                }
            }
        }
        if let assocLine = fields["Assoc. Bundle IDs"] {
            // Format: "[ com.id1, com.id2 ]"
            let cleaned = assocLine
                .trimmingCharacters(in: CharacterSet(charactersIn: "[] "))
            assocBundleIDs = cleaned.components(separatedBy: ", ")
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
        }

        let uuid = fields["UUID"] ?? UUID().uuidString
        let name = fields["Name"] ?? fields["Identifier"] ?? "Unknown"
        let identifier = fields["Identifier"]
        let itemType = fields["Type"]
        let developerName = fields["Developer Name"]
        let teamID = fields["Team Identifier"]
        let bundleID = fields["Bundle Identifier"]

        // Parse URL
        var url = fields["URL"]
        if let u = url, u.hasPrefix("file://") {
            url = u.removingPercentEncoding ?? u
            url = url?.replacingOccurrences(of: "file://", with: "")
        }

        // Parse Executable Path
        let execPath = fields["Executable Path"]

        // Parse disposition
        let disposition = fields["Disposition"] ?? ""
        let isEnabled = disposition.contains("enabled")
        let isAllowed = !disposition.contains("disallowed")

        // Parse type code
        let typeCode = parseTypeCode(itemType)

        // Determine run context from type
        let runContext: RunContext = {
            switch typeCode {
            case .loginItem, .app: return .login
            case .legacyAgent, .agent: return .login
            case .legacyDaemon, .daemon: return .boot
            case .backgroundAppRefresh: return .onDemand
            default: return .onDemand
            }
        }()

        // Skip pure "developer" container records that just group sub-items
        // unless they have a URL (i.e., they're actual apps)
        if typeCode == .developer && url == nil && execPath == nil {
            return nil
        }

        // Determine owner
        let owner: ItemOwner = {
            if let uid = uid {
                if uid == 0 || uid == -2 { return .system }
                return .user(PathUtilities.currentUser)
            }
            return .system
        }()

        // Resolve executable for .app bundles
        let resolvedExecPath: String?
        if let ep = execPath {
            resolvedExecPath = ep
        } else if let u = url, u.hasSuffix(".app") || u.hasSuffix(".app/") {
            resolvedExecPath = resolveAppExecutable(u)
        } else {
            resolvedExecPath = nil
        }

        // Build metadata
        var metadata: [String: PlistValue] = [
            "Source": .string("sfltool dumpbtm"),
        ]
        if let t = itemType { metadata["BTMType"] = .string(t) }
        if let d = developerName { metadata["DeveloperName"] = .string(d) }
        if let t = teamID { metadata["TeamIdentifier"] = .string(t) }
        if let b = bundleID { metadata["BundleIdentifier"] = .string(b) }
        if !disposition.isEmpty { metadata["Disposition"] = .string(disposition) }
        if !isAllowed { metadata["Disallowed"] = .bool(true) }
        if let flags = fields["Flags"] { metadata["Flags"] = .string(flags) }
        if let gen = fields["Generation"] { metadata["Generation"] = .string(gen) }
        if let parent = fields["Parent Identifier"] { metadata["ParentIdentifier"] = .string(parent) }
        if !embeddedItems.isEmpty {
            metadata["EmbeddedItems"] = .array(embeddedItems.map { .string($0) })
        }
        if !assocBundleIDs.isEmpty {
            metadata["AssocBundleIDs"] = .array(assocBundleIDs.map { .string($0) })
        }

        let displayName: String
        if name == identifier || name == "Unknown" {
            displayName = developerName ?? name
        } else {
            displayName = name
        }

        let item = PersistenceItem(
            category: category,
            name: displayName,
            label: identifier ?? bundleID,
            configPath: url,
            executablePath: resolvedExecPath,
            isEnabled: isEnabled,
            runContext: runContext,
            owner: owner,
            rawMetadata: metadata
        )

        return ParsedItem(uuid: uuid, item: item)
    }

    // MARK: - Helpers

    private func extractUID(from section: String) -> Int? {
        // "Records for UID 501 : ..."
        guard let range = section.range(of: "Records for UID ") else { return nil }
        let after = section[range.upperBound...]
        let uidStr = after.prefix(while: { $0.isNumber || $0 == "-" })
        return Int(uidStr)
    }

    private enum BTMType {
        case app, loginItem, agent, legacyAgent, daemon, legacyDaemon
        case developer, spotlight, quicklook, dockTile, backgroundAppRefresh
        case unknown
    }

    private func parseTypeCode(_ typeString: String?) -> BTMType {
        guard let t = typeString?.lowercased() else { return .unknown }
        if t.contains("legacy daemon") { return .legacyDaemon }
        if t.contains("legacy agent") { return .legacyAgent }
        if t.contains("login item") { return .loginItem }
        if t.contains("daemon") { return .daemon }
        if t.contains("agent") { return .agent }
        if t.contains("app") && !t.contains("background") { return .app }
        if t.contains("developer") { return .developer }
        if t.contains("spotlight") { return .spotlight }
        if t.contains("quicklook") { return .quicklook }
        if t.contains("dock tile") { return .dockTile }
        if t.contains("background app refresh") { return .backgroundAppRefresh }
        return .unknown
    }

    private func resolveAppExecutable(_ appPath: String) -> String? {
        let infoPlistPath = (appPath as NSString).appendingPathComponent("Contents/Info.plist")
        guard let dict = try? PlistParser().parse(at: infoPlistPath),
              let execName = dict["CFBundleExecutable"] as? String else {
            return nil
        }
        let execPath = (appPath as NSString)
            .appendingPathComponent("Contents/MacOS/\(execName)")
        return PathUtilities.exists(execPath) ? execPath : nil
    }
}
