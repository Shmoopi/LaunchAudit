import Foundation

public struct PAMScanner: PersistenceScanner {
    public let category = PersistenceCategory.pamModules
    public let requiresPrivilege = false

    /// Known Apple-shipped PAM modules (macOS).
    /// Includes every .so in /usr/lib/pam/ on the sealed system volume,
    /// matched with or without the .2/.1 version suffix.
    private static let appleModules: Set<String> = [
        // Core authentication
        "pam_opendirectory.so", "pam_unix.so", "pam_deny.so",
        "pam_permit.so", "pam_env.so", "pam_rootok.so",
        "pam_group.so", "pam_sacl.so", "pam_smartcard.so",
        "pam_tid.so", "pam_localauthentication.so", "pam_nologin.so",
        "pam_mount.so", "pam_launchd.so", "pam_uwtmp.so",
        "pam_self.so",
        // Kerberos, NTLM, and other Apple-shipped modules
        "pam_krb5.so", "pam_ntlm.so", "pam_aks.so",
        "pam_basesystem.so",
    ]

    /// Check if a module name matches a known Apple module, ignoring
    /// version suffixes like .so.2 or .so.1.
    private static func isAppleModule(_ moduleName: String) -> Bool {
        if appleModules.contains(moduleName) { return true }
        // Strip version suffix: "pam_deny.so.2" -> "pam_deny.so"
        if let range = moduleName.range(of: ".so.", options: .literal) {
            let base = String(moduleName[..<range.upperBound].dropLast(1))
            return appleModules.contains(base)
        }
        return false
    }

    /// Standard system directory where PAM .so modules live on macOS.
    private static let moduleSearchDirs = [
        "/usr/lib/pam",
        "/usr/local/lib/pam",
    ]

    public var scanPaths: [String] {
        ["/etc/pam.d"] + Self.moduleSearchDirs
    }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        var items: [PersistenceItem] = []

        // --- Phase 1: Scan PAM config files ---
        let pamDir = "/etc/pam.d"
        guard PathUtilities.exists(pamDir) else { return items }

        let configs = PathUtilities.listFiles(in: pamDir)
        for configPath in configs {
            let name = (configPath as NSString).lastPathComponent
            guard !name.hasPrefix(".") else { continue }
            guard let content = try? String(contentsOfFile: configPath, encoding: .utf8) else { continue }

            let timestamps = PathUtilities.timestamps(for: configPath)
            var referencedModules: [(name: String, path: String?)] = []
            var nonStandardModules: [String] = []

            for line in content.components(separatedBy: "\n") {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { continue }

                // PAM lines: type control module-path [module-arguments]
                let parts = trimmed.components(separatedBy: .whitespaces).filter { !$0.isEmpty }
                guard parts.count >= 3 else { continue }

                let modulePath = parts[2]
                let moduleName = (modulePath as NSString).lastPathComponent

                let resolvedPath = Self.resolveModulePath(modulePath)
                referencedModules.append((name: moduleName, path: resolvedPath))

                if !Self.isAppleModule(moduleName) {
                    nonStandardModules.append(moduleName)
                }
            }

            var riskLevel: RiskLevel = .informational
            var riskReasons: [String] = []

            if !nonStandardModules.isEmpty {
                riskLevel = .high
                riskReasons.append("Non-standard PAM modules: \(nonStandardModules.joined(separator: ", "))")
            }

            // All configs in /etc/pam.d/ are on the sealed system volume
            let source: ItemSource = .apple

            items.append(PersistenceItem(
                category: category,
                name: "PAM config: \(name)",
                configPath: configPath,
                isEnabled: true,
                runContext: .triggered,
                owner: .system,
                riskLevel: riskLevel,
                riskReasons: riskReasons,
                source: source,
                timestamps: timestamps,
                rawMetadata: [
                    "ConfigName": .string(name),
                    "ReferencedModules": .array(referencedModules.map { .string($0.name) }),
                    "NonStandardModules": .array(nonStandardModules.map { .string($0) }),
                ]
            ))
        }

        // --- Phase 2: Scan actual .so module binaries ---
        var seenModules: Set<String> = []

        for dir in Self.moduleSearchDirs {
            guard PathUtilities.exists(dir) else { continue }
            let files = PathUtilities.listFiles(in: dir, withExtension: "so")
                + PathUtilities.listFiles(in: dir).filter { $0.hasSuffix(".so.2") || $0.hasSuffix(".so.1") }

            for modulePath in files {
                let moduleName = (modulePath as NSString).lastPathComponent
                guard !seenModules.contains(moduleName) else { continue }
                seenModules.insert(moduleName)

                let timestamps = PathUtilities.timestamps(for: modulePath)
                let isKnownApple = Self.isAppleModule(moduleName)

                // For modules in /usr/lib/pam (SIP-protected), Apple modules
                // are on the sealed system volume.  Non-standard ones are notable.
                let source: ItemSource = isKnownApple ? .apple : .unknown
                let riskLevel: RiskLevel = isKnownApple ? .informational : .high
                var riskReasons: [String] = []
                if !isKnownApple {
                    riskReasons.append("Non-standard PAM module binary")
                }

                items.append(PersistenceItem(
                    category: category,
                    name: moduleName,
                    label: moduleName,
                    configPath: nil,
                    executablePath: modulePath,
                    isEnabled: true,
                    runContext: .triggered,
                    owner: .system,
                    riskLevel: riskLevel,
                    riskReasons: riskReasons,
                    source: source,
                    timestamps: timestamps,
                    rawMetadata: [
                        "ModulePath": .string(modulePath),
                        "AppleProvided": .bool(isKnownApple),
                    ]
                ))
            }
        }

        return items
    }

    /// Resolve a module path reference from a PAM config to an absolute path.
    /// PAM configs may use bare names ("pam_deny.so") or absolute paths.
    private static func resolveModulePath(_ modulePath: String) -> String? {
        if modulePath.hasPrefix("/") {
            return PathUtilities.exists(modulePath) ? modulePath : nil
        }
        for dir in moduleSearchDirs {
            let full = (dir as NSString).appendingPathComponent(modulePath)
            if PathUtilities.exists(full) { return full }
        }
        return nil
    }
}
