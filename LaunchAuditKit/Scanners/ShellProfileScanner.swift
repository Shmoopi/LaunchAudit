import Foundation

public struct ShellProfileScanner: PersistenceScanner {
    public let category = PersistenceCategory.shellProfiles
    public let requiresPrivilege = false

    public var scanPaths: [String] {
        let systemPaths = [
            "/etc/profile",
            "/etc/bashrc",
            "/etc/zshrc",
            "/etc/zshenv",
            "/etc/zprofile"
        ]
        let userPaths = [
            "~/.bashrc",
            "~/.bash_profile",
            "~/.bash_login",
            "~/.profile",
            "~/.zshrc",
            "~/.zshenv",
            "~/.zprofile",
            "~/.zlogin"
        ].map { PathUtilities.expandTilde($0) }

        return systemPaths + userPaths
    }

    public init() {}

    /// Patterns that indicate potentially suspicious content in shell profiles.
    private static let suspiciousPatterns: [(pattern: String, reason: String)] = [
        ("curl.*|.*sh", "Downloads and executes remote script"),
        ("wget.*|.*sh", "Downloads and executes remote script"),
        ("curl.*|.*bash", "Downloads and pipes to bash"),
        ("base64.*decode", "Base64 decoding (potential obfuscation)"),
        ("eval.*\\$\\(", "Eval with command substitution"),
        ("nc\\s+-l", "Netcat listener (potential reverse shell)"),
        ("ncat.*-e", "Ncat with execute (potential reverse shell)"),
        ("/dev/tcp/", "Bash TCP redirection (potential reverse shell)"),
        ("python.*-c.*import.*socket", "Python socket code (potential reverse shell)"),
        ("DYLD_INSERT_LIBRARIES", "Dynamic library injection variable"),
        ("launchctl.*load", "Loading launchd jobs from shell profile"),
        ("osascript.*-e", "AppleScript execution from shell"),
        ("openssl.*enc", "OpenSSL encryption/decryption (potential obfuscation)"),
    ]

    public func scan() async throws -> [PersistenceItem] {
        var items: [PersistenceItem] = []

        for path in scanPaths {
            guard PathUtilities.exists(path) else { continue }

            let timestamps = PathUtilities.timestamps(for: path)
            let filename = (path as NSString).lastPathComponent
            let isSystem = path.hasPrefix("/etc")
            let owner: ItemOwner = isSystem ? .system : .user(PathUtilities.currentUser)

            var riskReasons: [String] = []
            var riskLevel: RiskLevel = .informational

            // Check file content for suspicious patterns
            if let content = try? String(contentsOfFile: path, encoding: .utf8) {
                let lowered = content.lowercased()
                for (pattern, reason) in Self.suspiciousPatterns {
                    if lowered.range(of: pattern, options: .regularExpression) != nil {
                        riskReasons.append(reason)
                        riskLevel = .high
                    }
                }

                // Check file size — unusually large shell profiles are suspicious
                if content.count > 50_000 {
                    riskReasons.append("Unusually large shell profile (\(content.count) bytes)")
                    if riskLevel < .medium { riskLevel = .medium }
                }
            }

            items.append(PersistenceItem(
                category: category,
                name: filename,
                configPath: path,
                executablePath: path,
                isEnabled: true,
                runContext: .login,
                owner: owner,
                riskLevel: riskLevel,
                riskReasons: riskReasons,
                timestamps: timestamps,
                rawMetadata: [
                    "ShellType": .string(filename.contains("zsh") ? "zsh" : filename.contains("bash") ? "bash" : "sh"),
                    "Scope": .string(isSystem ? "system" : "user")
                ]
            ))
        }

        return items
    }
}
