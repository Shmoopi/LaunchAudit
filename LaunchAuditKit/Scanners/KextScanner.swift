import Foundation

public struct KextScanner: PersistenceScanner {
    public let category = PersistenceCategory.kernelExtensions
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        [
            "/Library/Extensions",
            "/System/Library/Extensions"
        ]
    }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        var items: [PersistenceItem] = []

        // Scan on-disk kext bundles (third-party)
        let thirdPartyDir = "/Library/Extensions"
        if PathUtilities.exists(thirdPartyDir) {
            let kexts = PathUtilities.listBundles(in: thirdPartyDir, withExtension: "kext")
            for kextPath in kexts {
                if let item = parseKext(at: kextPath, owner: .system) {
                    items.append(item)
                }
            }
        }

        // Query loaded kexts via kmutil — direct exec, no /bin/sh fork.
        if let output = await ProcessRunner.shared.tryRun(
            "/usr/bin/kmutil", arguments: ["showloaded", "--show", "loaded"]
        ) {
            let loaded = Self.parseKmutilOutput(output)
            // Mark on-disk items as running if they appear in loaded list
            for (index, item) in items.enumerated() {
                if let label = item.label, loaded.contains(label) {
                    var modified = item
                    modified = PersistenceItem(
                        id: item.id,
                        category: item.category,
                        name: item.name,
                        label: item.label,
                        configPath: item.configPath,
                        executablePath: item.executablePath,
                        arguments: item.arguments,
                        isEnabled: true,
                        runContext: .boot,
                        owner: item.owner,
                        signingInfo: item.signingInfo,
                        riskLevel: item.riskLevel,
                        riskReasons: item.riskReasons,
                        source: item.source,
                        timestamps: item.timestamps,
                        rawMetadata: item.rawMetadata.merging(["Loaded": .bool(true)]) { _, new in new }
                    )
                    items[index] = modified
                }
            }
        }

        return items
    }

    private func parseKext(at path: String, owner: ItemOwner) -> PersistenceItem? {
        let name = ((path as NSString).lastPathComponent as NSString).deletingPathExtension
        let infoPlistPath = (path as NSString).appendingPathComponent("Contents/Info.plist")
        let timestamps = PathUtilities.timestamps(for: path)

        var label: String?
        var metadata: [String: PlistValue] = [:]

        if PathUtilities.exists(infoPlistPath),
           let dict = try? PlistParser().parse(at: infoPlistPath) {
            label = dict["CFBundleIdentifier"] as? String
            metadata = PlistParser().toMetadata(dict)
        }

        return PersistenceItem(
            category: category,
            name: name,
            label: label,
            configPath: path,
            isEnabled: true,
            runContext: .boot,
            owner: owner,
            timestamps: timestamps,
            rawMetadata: metadata
        )
    }

    /// Test seam — exposes the strict parser without going through scan().
    func parseLoadedBundleIDsForTesting(_ output: String) -> Set<String> {
        Self.parseKmutilOutput(output)
    }

    /// Compiled once. Reverse-DNS bundle identifier:
    ///   `<segment>(.<segment>)+` where each segment starts with a letter
    ///   and contains only letters, digits, `_`, or `-`.
    /// Rejects IPs (digit-led segments), parenthesised tokens, paths, and
    /// version strings — the false positives the previous loose check produced.
    private static let bundleIDRegex: NSRegularExpression = {
        // swiftlint:disable:next force_try
        try! NSRegularExpression(
            pattern: #"^[A-Za-z][A-Za-z0-9_-]*(?:\.[A-Za-z][A-Za-z0-9_-]*)+$"#
        )
    }()

    private static func parseKmutilOutput(_ output: String) -> Set<String> {
        var bundleIDs = Set<String>()
        for line in output.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            for part in trimmed.split(separator: " ", omittingEmptySubsequences: true) {
                let token = String(part)
                let range = NSRange(location: 0, length: (token as NSString).length)
                if bundleIDRegex.firstMatch(in: token, range: range) != nil {
                    bundleIDs.insert(token)
                }
            }
        }
        return bundleIDs
    }
}
