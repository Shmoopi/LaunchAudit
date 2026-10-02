import Foundation

public struct ProfileScanner: PersistenceScanner {
    public let category = PersistenceCategory.configurationProfiles
    public let requiresPrivilege = true

    public var scanPaths: [String] {
        ["/var/db/ConfigurationProfiles", "/Library/Managed Preferences"]
    }

    public init() {}

    public func scan() async throws -> ScanOutcome {
        var outcome = ScanOutcome()

        // Root when we have it, the privileged helper when we do not.
        let output: String
        do {
            output = try await PrivilegedCommand.listConfigurationProfiles().output
        } catch {
            outcome.errors.append(ScanError(
                category: category,
                message: "Could not list configuration profiles: "
                    + "\(error.localizedDescription). This category needs root — "
                    + "either approve the LaunchAudit helper in System Settings → "
                    + "General → Login Items & Extensions, or run `sudo launchaudit scan`.",
                isPermissionDenied: true
            ))
            return outcome
        }

        let trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
        // As a normal user `profiles list` returns an empty dict rather than an
        // error, which used to surface as a bare "0 profiles" with no explanation.
        guard !trimmed.isEmpty, trimmed != "<dict/>" else {
            outcome.errors.append(ScanError(
                category: category,
                message: "`profiles list` returned nothing. This normally means the "
                    + "scan lacked root privileges rather than that no profiles exist.",
                isPermissionDenied: !PathUtilities.isRoot
            ))
            return outcome
        }

        if trimmed.hasPrefix("<?xml") || trimmed.hasPrefix("<plist") {
            outcome.items = parseProfilesXML(output)
        } else {
            outcome.items = parseProfilesText(output)
        }
        return outcome
    }

    /// Parse `profiles list -output stdout-xml`.
    ///
    /// The top-level dictionary is keyed by domain: `_computerlevel` for
    /// device-wide profiles and one key per user for user-scoped ones. Reading only
    /// `_computerlevel` — which is what this used to do — silently dropped every
    /// per-user profile.
    func parseProfilesXML(_ xml: String) -> [PersistenceItem] {
        guard let data = xml.data(using: .utf8),
              let plist = try? PlistParser().parse(data: data) else {
            return []
        }

        var items: [PersistenceItem] = []
        for (domain, value) in plist {
            guard let profiles = value as? [[String: Any]] else { continue }
            let owner: ItemOwner = domain == "_computerlevel" ? .system : .user(domain)
            for profile in profiles {
                if let item = profileToItem(profile, owner: owner, domain: domain) {
                    items.append(item)
                }
            }
        }
        return items
    }

    private func profileToItem(
        _ dict: [String: Any],
        owner: ItemOwner,
        domain: String
    ) -> PersistenceItem? {
        let name = dict["ProfileDisplayName"] as? String
            ?? dict["ProfileIdentifier"] as? String
            ?? "Unknown Profile"
        let identifier = dict["ProfileIdentifier"] as? String
        let organization = dict["ProfileOrganization"] as? String

        var metadata = PlistParser().toMetadata(dict)
        metadata["Domain"] = .string(domain)

        var reasons: [String] = []
        // Payloads that can install persistence or silently add extensions.
        if let payloads = dict["ProfileItems"] as? [[String: Any]] {
            let types = payloads.compactMap { $0["PayloadType"] as? String }
            let notable = types.filter {
                $0.contains("MCX") || $0.contains("loginwindow")
                    || $0.contains("com.apple.ManagedClient")
                    || $0.lowercased().contains("extension")
            }
            if !notable.isEmpty {
                reasons.append(
                    "Contains payloads that can configure startup items or extensions: "
                        + notable.joined(separator: ", ")
                )
            }
            metadata["PayloadTypes"] = .string(types.joined(separator: ", "))
        }

        return PersistenceItem(
            category: category,
            name: name,
            label: identifier,
            isEnabled: true,
            runContext: .boot,
            owner: owner,
            riskReasons: reasons,
            source: organization.map { .thirdParty($0) } ?? .unknown,
            rawMetadata: metadata
        )
    }

    /// Parse the plain-text fallback format.
    ///
    /// Lines look like `attribute: profileDisplayName: MDM: Corp Profile`. Taking
    /// the component after the *last* colon yields "Corp Profile" only by accident
    /// and truncates any name containing a colon; the value is everything after the
    /// attribute name.
    func parseProfilesText(_ output: String) -> [PersistenceItem] {
        var items: [PersistenceItem] = []
        var currentName: String?
        var currentID: String?

        func flush() {
            guard let name = currentName ?? currentID else { return }
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

        for line in output.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            if trimmed.isEmpty {
                flush()
                continue
            }
            guard trimmed.hasPrefix("attribute:") else { continue }

            // attribute: <key>: <value>
            let body = trimmed.dropFirst("attribute:".count)
                .trimmingCharacters(in: .whitespaces)
            guard let separator = body.range(of: ": ") else { continue }
            let key = String(body[body.startIndex..<separator.lowerBound])
                .trimmingCharacters(in: .whitespaces)
            let value = String(body[separator.upperBound...])
                .trimmingCharacters(in: .whitespaces)

            switch key {
            case "profileIdentifier": currentID = value
            case "profileDisplayName": currentName = value
            default: break
            }
        }
        flush()

        return items
    }
}
