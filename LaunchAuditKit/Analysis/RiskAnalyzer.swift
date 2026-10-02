import Foundation

public struct RiskAnalyzer: Sendable {

    private let classifier = RiskClassifier()

    public init() {}

    /// Analyze a persistence item and assign a risk level with reasons.
    ///
    /// Risk classification is delegated to ``RiskClassifier``, which evaluates
    /// signing trust, mechanism severity, execution context, location, temporal,
    /// content, interpreter and entitlement signals as independent dimensions.
    /// This method then handles source attribution from signing info.
    public func analyze(_ item: PersistenceItem) -> PersistenceItem {
        var result = item

        // Source attribution happens *before* classification so the classifier
        // sees the authoritative source.
        result.source = resolveSource(for: item)

        let assessment = classifier.classify(result)
        result.riskLevel = assessment.level
        result.riskReasons = assessment.reasons
        result.riskMitigations = assessment.mitigations
        return result
    }

    /// Determine who provided this item.
    ///
    /// The code signature is the only authoritative signal. A bundle identifier or
    /// launchd label is chosen by whoever wrote the file, so it can claim
    /// `com.apple.*` freely — it is used only as a last resort for items that have
    /// no binary to verify, and never to conclude "Apple" for something that has a
    /// signature saying otherwise.
    private func resolveSource(for item: PersistenceItem) -> ItemSource {
        if let signing = item.signingInfo, signing.isSigned {
            if signing.isAppleSigned {
                // An Apple-signed interpreter running a third party's script is
                // not Apple's software.
                return item.isInterpreterFronted ? .unknown : .apple
            }
            if let name = extractDeveloperName(from: signing) {
                return .thirdParty(name)
            }
            if let team = signing.teamIdentifier {
                return .thirdParty(team)
            }
            return .unknown
        }

        // Unsigned, or nothing to verify. Content on the sealed system volume is
        // Apple's by construction — SIP protects it and there is no separate
        // executable to check.
        if let config = item.configPath, PathUtilities.isAppleOwnedPath(config) {
            return .apple
        }

        // Keep an explicit `.apple` a scanner set from a protected path, but never
        // upgrade `.unknown` to `.apple` on the strength of a label alone.
        if case .apple = item.source, item.signingInfo == nil,
           let config = item.configPath, PathUtilities.isAppleOwnedPath(config) {
            return .apple
        }

        if case .thirdParty = item.source { return item.source }
        return .unknown
    }

    /// Check if a label matches known Apple-deployed patterns.
    ///
    /// Retained for display grouping only. This must not be used to decide trust:
    /// a label is attacker-chosen. See `resolveSource`.
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
    ///
    /// Display only. The certificate subject is chosen by the issuer, so this
    /// string never participates in a trust decision.
    func extractDeveloperName(from signing: SigningInfo) -> String? {
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
}
