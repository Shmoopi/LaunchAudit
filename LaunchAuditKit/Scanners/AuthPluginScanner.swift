import Foundation

public struct AuthPluginScanner: PersistenceScanner {
    public let category = PersistenceCategory.authorizationPlugins
    public let requiresPrivilege = false

    /// `/System/Library/CoreServices/SecurityAgentPlugins` holds the bundles the
    /// authorization database actually references (HomeDirMechanism, MCXMechanism,
    /// CryptoTokenKit). Scanning only `/Library/...` meant the correlation below
    /// could never find its targets.
    private let directories = [
        "/Library/Security/SecurityAgentPlugins",
        "/System/Library/CoreServices/SecurityAgentPlugins",
    ]

    /// Authorization rules worth inspecting: these run during login and unlock.
    private let authorizationRules = [
        "system.login.console",
        "system.login.screensaver",
        "authenticate",
    ]

    public var scanPaths: [String] { directories }

    public init() {}

    public func scan() async throws -> ScanOutcome {
        let scanner = DirectoryBundleScanner()
        var outcome = ScanOutcome()
        outcome.merge(scanner.scanBundles(
            in: directories,
            bundleExtension: "bundle",
            category: category,
            owner: .system,
            runContext: .onDemand
        ))

        // Mechanisms referenced by the authorization database, as plugin name →
        // the full mechanism strings that referenced it.
        var references: [String: [String]] = [:]
        for rule in authorizationRules {
            guard let output = await ProcessRunner.shared.tryRun(
                "/usr/bin/security",
                arguments: ["authorizationdb", "read", rule],
                timeout: 5
            ) else { continue }

            for mechanism in Self.parseMechanisms(output) {
                guard let plugin = Self.pluginName(from: mechanism) else { continue }
                references[plugin, default: []].append("\(rule): \(mechanism)")
            }
        }

        for index in outcome.items.indices {
            let name = outcome.items[index].name
            guard let referencedBy = references[name] else { continue }
            // A plugin wired into the login chain runs at authentication time.
            outcome.items[index].runContext = .login
            outcome.items[index].riskReasons.append(
                "Wired into the authentication chain: \(referencedBy.joined(separator: ", "))"
            )
        }

        return outcome
    }

    /// Extract the `mechanisms` array from `security authorizationdb read` output.
    ///
    /// The output is a property list, so parse it as one. The previous
    /// implementation string-matched for `privileged` or `plugin`, which dropped
    /// every unprivileged mechanism (`MCXMechanism:login`, `CryptoTokenKit:login`).
    static func parseMechanisms(_ output: String) -> [String] {
        guard let data = output.data(using: .utf8),
              let dict = try? PlistParser().parse(data: data),
              let mechanisms = dict["mechanisms"] as? [String] else {
            return []
        }
        return mechanisms
    }

    /// Mechanism strings look like `HomeDirMechanism:login,privileged` or
    /// `builtin:prelogin`. The plugin name is the part before the first colon.
    ///
    /// Comparing the whole mechanism string against a bundle's basename — which is
    /// what used to happen — made the two sets disjoint by construction, so the
    /// correlation never matched anything.
    static func pluginName(from mechanism: String) -> String? {
        let name = mechanism.components(separatedBy: ":").first ?? mechanism
        // `builtin:` and `loginwindow:` are not loadable plugin bundles.
        guard name != "builtin", name != "loginwindow", !name.isEmpty else { return nil }
        return name
    }
}
