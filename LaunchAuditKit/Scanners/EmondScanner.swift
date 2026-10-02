import Foundation

/// The Event Monitor daemon.
///
/// Apple **removed emond in macOS 13**, and this project targets macOS 14+, so
/// `/etc/emond.d` and `/private/var/db/emondClients` do not exist on any supported
/// system. The scanner is kept as a **legacy tripwire**: it costs two `exists`
/// checks, stays silent when the paths are absent, and treats any hit as high risk
/// — because on a supported OS these directories are not created by the operating
/// system, so something else put them there.
///
/// It is explicitly *not* privileged. It used to declare `requiresPrivilege = true`,
/// which made every unprivileged headless run emit a "Skipped — requires root"
/// warning for a subsystem that cannot exist. That is manufactured noise in the
/// coverage report.
public struct EmondScanner: PersistenceScanner {
    public let category = PersistenceCategory.emondRules
    public let requiresPrivilege = false

    private let rulesDirectory = "/etc/emond.d/rules"
    private let clientsDirectory = "/private/var/db/emondClients"

    public var scanPaths: [String] { [rulesDirectory, clientsDirectory] }

    public init() {}

    public func scan() async throws -> ScanOutcome {
        var outcome = ScanOutcome()

        let legacyReason = "emond was removed in macOS 13 — this path should not exist "
            + "on a supported system"

        let (rules, ruleErrors) = entries(in: rulesDirectory, withExtension: "plist")
        outcome.errors += ruleErrors
        for plistPath in rules {
            let name = ((plistPath as NSString).lastPathComponent as NSString)
                .deletingPathExtension

            // Merge rather than replace: assigning the parsed plist over the base
            // metadata discarded the Source/Type keys the scanner had just set.
            var metadata: [String: PlistValue] = [
                "Source": .string("emond.d/rules"),
                "Type": .string("emond rule"),
            ]
            if let dict = try? PlistParser().parse(at: plistPath) {
                metadata.merge(PlistParser().toMetadata(dict)) { _, new in new }
            }

            outcome.items.append(PersistenceItem(
                category: category,
                name: name,
                configPath: plistPath,
                isEnabled: true,
                runContext: .triggered,
                owner: .system,
                riskLevel: .high,
                riskReasons: [legacyReason],
                timestamps: PathUtilities.timestamps(for: plistPath),
                rawMetadata: metadata
            ))
        }

        let (clients, clientErrors) = entries(in: clientsDirectory)
        outcome.errors += clientErrors
        for file in clients {
            let name = (file as NSString).lastPathComponent
            outcome.items.append(PersistenceItem(
                category: category,
                name: "emond client: \(name)",
                configPath: file,
                isEnabled: true,
                runContext: .triggered,
                owner: .system,
                riskLevel: .high,
                riskReasons: [legacyReason],
                timestamps: PathUtilities.timestamps(for: file),
                rawMetadata: [
                    "Source": .string("emondClients"),
                    "Type": .string("emond client"),
                ]
            ))
        }

        return outcome
    }
}
