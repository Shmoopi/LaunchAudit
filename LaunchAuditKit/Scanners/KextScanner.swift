import Foundation

public struct KextScanner: PersistenceScanner {
    public let category = PersistenceCategory.kernelExtensions
    public let requiresPrivilege = false

    /// Staged copies live under `/Library/StagedExtensions`; kexts approved by the
    /// user are copied there by the kext management subsystem.
    public var scanPaths: [String] {
        [
            "/Library/Extensions",
            "/Library/StagedExtensions/Library/Extensions",
            "/System/Library/Extensions",
        ]
    }

    public init() {}

    public func scan() async throws -> ScanOutcome {
        var outcome = ScanOutcome()

        // Walk every directory `scanPaths` declares. `/Library/StagedExtensions`
        // and `/System/Library/Extensions` were declared but never opened.
        for directory in scanPaths {
            guard PathUtilities.exists(directory) else { continue }
            for kextPath in PathUtilities.listBundles(in: directory, withExtension: "kext") {
                if let item = parseKext(at: kextPath, owner: .system) {
                    outcome.items.append(item)
                }
            }
        }

        // Query loaded kexts via kmutil — direct exec, no /bin/sh fork.
        guard let output = await ProcessRunner.shared.tryRun(
            "/usr/bin/kmutil", arguments: ["showloaded", "--show", "loaded"], timeout: 15
        ) else {
            outcome.errors.append(ScanError(
                category: category,
                message: "kmutil showloaded produced no output — loaded-kext state unknown",
                isPermissionDenied: false
            ))
            return outcome
        }

        let loaded = Self.parseKmutilOutput(output)
        var onDisk = Set<String>()

        for index in outcome.items.indices {
            guard let label = outcome.items[index].label else { continue }
            onDisk.insert(label)
            guard loaded.contains(label) else { continue }
            // Fields are `var` now, so no full-struct copy is needed. The old
            // hand-rolled reconstruction silently dropped any newly added field.
            outcome.items[index].isEnabled = true
            outcome.items[index].runContext = .boot
            outcome.items[index].rawMetadata["Loaded"] = .bool(true)
        }

        // A kext loaded in the kernel with no bundle on disk is a genuine anomaly
        // and used to be invisible: the loaded list was only ever used to annotate
        // items already discovered on disk.
        for label in loaded.subtracting(onDisk) {
            // Apple's own kexts live on the sealed volume, which is not scanned.
            guard !RiskAnalyzer.isKnownAppleLabel(label) else { continue }
            outcome.items.append(PersistenceItem(
                category: category,
                name: label,
                label: label,
                isEnabled: true,
                runContext: .boot,
                owner: .system,
                riskLevel: .high,
                riskReasons: [
                    "Kernel extension is loaded but has no bundle in any scanned "
                        + "extension directory",
                ],
                rawMetadata: [
                    "Loaded": .bool(true),
                    "OnDisk": .bool(false),
                ]
            ))
        }

        return outcome
    }

    private func parseKext(at path: String, owner: ItemOwner) -> PersistenceItem? {
        let name = ((path as NSString).lastPathComponent as NSString).deletingPathExtension
        let infoPlistPath = (path as NSString).appendingPathComponent("Contents/Info.plist")
        let timestamps = PathUtilities.timestamps(for: path)

        var label: String?
        var executablePath: String?
        var metadata: [String: PlistValue] = [:]

        if PathUtilities.exists(infoPlistPath),
           let dict = try? PlistParser().parse(at: infoPlistPath) {
            label = dict["CFBundleIdentifier"] as? String
            metadata = PlistParser().toMetadata(dict)
            // Resolve the kext binary so its signature is verified. Kernel
            // extensions are the highest-privilege code on the machine and none of
            // them was being checked, because no executable path was ever set.
            if let execName = dict["CFBundleExecutable"] as? String {
                let candidate = (path as NSString)
                    .appendingPathComponent("Contents/MacOS/\(execName)")
                executablePath = PathUtilities.exists(candidate) ? candidate : nil
            }
        }

        return PersistenceItem(
            category: category,
            name: name,
            label: label,
            configPath: path,
            executablePath: executablePath,
            isEnabled: true,
            runContext: .boot,
            owner: owner,
            source: PathUtilities.isAppleOwnedPath(path) ? .apple : .unknown,
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
