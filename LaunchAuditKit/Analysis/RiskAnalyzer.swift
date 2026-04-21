import Foundation

public struct RiskAnalyzer: Sendable {

    private let classifier = RiskClassifier()

    public init() {}

    /// Analyze a persistence item and assign a risk level with reasons.
    ///
    /// Risk classification is delegated to ``RiskClassifier``, which evaluates
    /// signing trust, mechanism severity, execution context, location, temporal
    /// signals, and content signals as independent dimensions. This method then
    /// handles source attribution from signing info.
    public func analyze(_ item: PersistenceItem) -> PersistenceItem {
        // Delegate risk classification to the multi-dimensional classifier
        let (riskLevel, reasons) = classifier.classify(item)

        var result = item
        result.riskLevel = riskLevel
        result.riskReasons = reasons

        // Determine source from signing info — this is the authoritative signal.
        if let signing = item.signingInfo {
            if signing.isAppleSigned {
                result = withSource(result, .apple)
            } else if signing.isSigned {
                // Signed but NOT Apple-signed — always treat as third-party,
                // even if the scanner guessed .apple from path/label.
                let developerName = extractDeveloperName(from: signing)
                if let name = developerName {
                    result = withSource(result, .thirdParty(name))
                } else if let team = signing.teamIdentifier {
                    result = withSource(result, .thirdParty(team))
                } else {
                    result = withSource(result, .unknown)
                }
            }
            // If unsigned, leave the scanner-provided source (e.g. .apple
            // for sealed system volume scripts that aren't Mach-O binaries).
        } else if case .unknown = result.source {
            // No signing info and source is unknown — use label heuristic
            // as a fallback (e.g. orphaned plists where the binary is gone).
            if let label = item.label {
                if Self.isKnownAppleLabel(label) {
                    result = withSource(result, .apple)
                }
            }
        }

        return result
    }

    /// Check if a label matches known Apple-deployed patterns.
    /// Used as a fallback when code signing verification is unavailable.
    static func isKnownAppleLabel(_ label: String) -> Bool {
        let prefixes = [
            "com.apple.", "org.cups.", "org.apache.httpd",
            "org.openldap.", "org.net-snmp.", "com.openssh.", "com.vix.cron",
        ]
        for prefix in prefixes {
            if label.hasPrefix(prefix) { return true }
        }
        let exact: Set<String> = ["bootps", "ntalk", "ssh", "tftp"]
        return exact.contains(label)
    }

    /// Extract a human-readable developer name from the signing certificate chain.
    /// The leaf certificate (first in the chain) is typically
    /// "Developer ID Application: Company Name (TEAMID)" — extract just the company name.
    private func extractDeveloperName(from signing: SigningInfo) -> String? {
        guard let leaf = signing.signingAuthority.first else { return nil }

        // "Developer ID Application: Company Name (TEAMID)"
        // "Apple Development: developer@example.com (TEAMID)"
        // "3rd Party Mac Developer Application: Company (TEAMID)"
        if let colonRange = leaf.range(of: ": ") {
            var name = String(leaf[colonRange.upperBound...])
            // Strip trailing "(TEAMID)" if present
            if let parenRange = name.range(of: " (", options: .backwards) {
                name = String(name[..<parenRange.lowerBound])
            }
            return name.isEmpty ? nil : name
        }

        return nil
    }

    private func withSource(_ item: PersistenceItem, _ source: ItemSource) -> PersistenceItem {
        PersistenceItem(
            id: item.id,
            category: item.category,
            name: item.name,
            label: item.label,
            configPath: item.configPath,
            executablePath: item.executablePath,
            arguments: item.arguments,
            isEnabled: item.isEnabled,
            runContext: item.runContext,
            owner: item.owner,
            signingInfo: item.signingInfo,
            riskLevel: item.riskLevel,
            riskReasons: item.riskReasons,
            source: source,
            timestamps: item.timestamps,
            rawMetadata: item.rawMetadata
        )
    }
}
