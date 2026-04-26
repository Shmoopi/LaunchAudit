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
        ("curl.*\\|.*sh",             "Downloads and executes remote script"),
        ("wget.*\\|.*sh",             "Downloads and executes remote script"),
        ("curl.*\\|.*bash",           "Downloads and pipes to bash"),
        ("base64.*decode",            "Base64 decoding (potential obfuscation)"),
        ("eval.*\\$\\(",              "Eval with command substitution"),
        ("nc\\s+-l",                  "Netcat listener (potential reverse shell)"),
        ("ncat.*-e",                  "Ncat with execute (potential reverse shell)"),
        ("/dev/tcp/",                 "Bash TCP redirection (potential reverse shell)"),
        ("python.*-c.*import.*socket","Python socket code (potential reverse shell)"),
        ("DYLD_INSERT_LIBRARIES",     "Dynamic library injection variable"),
        ("launchctl.*load",           "Loading launchd jobs from shell profile"),
        ("osascript.*-e",             "AppleScript execution from shell"),
        ("openssl.*enc",              "OpenSSL encryption/decryption (potential obfuscation)"),
    ]

    /// Pre-compiled regexes — built once at process startup. The previous
    /// implementation re-compiled each pattern on every `range(of:options:)`
    /// call, which was the bulk of the per-file cost.
    private static let compiledPatterns: [(NSRegularExpression, String)] = {
        suspiciousPatterns.compactMap { entry in
            guard let regex = try? NSRegularExpression(
                pattern: entry.pattern, options: [.caseInsensitive]
            ) else { return nil }
            return (regex, entry.reason)
        }
    }()

    /// Walk file content once per pattern using pre-compiled regexes.
    /// Pre-compilation is the dominant speedup; case-insensitive flag avoids
    /// the prior `.lowercased()` copy of the entire file.
    /// Exposed `internal` for unit tests.
    static func suspiciousReasons(in content: String) -> [String] {
        let nsContent = content as NSString
        let range = NSRange(location: 0, length: nsContent.length)
        var reasons: [String] = []
        for (regex, reason) in compiledPatterns {
            if regex.firstMatch(in: content, range: range) != nil {
                reasons.append(reason)
            }
        }
        return reasons
    }

    public func scan() async throws -> [PersistenceItem] {
        var items: [PersistenceItem] = []
        var seenCanonicalPaths = Set<String>()

        for path in scanPaths {
            guard PathUtilities.exists(path) else { continue }

            // Resolve symlinks and normalize so the same underlying file is
            // never reported twice (e.g. /etc/zshrc -> /private/etc/zshrc).
            let canonicalPath = (path as NSString).resolvingSymlinksInPath
            guard seenCanonicalPaths.insert(canonicalPath).inserted else { continue }

            let timestamps = PathUtilities.timestamps(for: path)
            let filename = (path as NSString).lastPathComponent
            let isSystem = path.hasPrefix("/etc")
            let owner: ItemOwner = isSystem ? .system : .user(PathUtilities.currentUser)

            let content = try? String(contentsOfFile: path, encoding: .utf8)

            // Skip stock/unmodified profiles — they contain only comments,
            // whitespace, and default shell boilerplate. Nothing actionable.
            if let content, Self.isStockProfile(content) {
                continue
            }

            var riskReasons: [String] = []
            var riskLevel: RiskLevel = .informational

            // Check file content for suspicious patterns — single combined
            // regex pass over the original content (case-insensitive flag
            // replaces the prior full-content lowercase copy).
            if let content {
                let reasons = Self.suspiciousReasons(in: content)
                if !reasons.isEmpty {
                    riskReasons.append(contentsOf: reasons)
                    riskLevel = .high
                }

                // Check file size — unusually large shell profiles are suspicious
                if content.count > 50_000 {
                    riskReasons.append("Unusually large shell profile (\(content.count) bytes)")
                    if riskLevel < .medium { riskLevel = .medium }
                }
            }

            // Build a display name that distinguishes system files from user
            // dotfiles (e.g. "zshrc (system)" vs ".zshrc").
            let displayName: String
            if isSystem {
                displayName = "\(filename) (system)"
            } else {
                displayName = filename
            }

            let shellType: String = {
                let lower = filename.lowercased()
                if lower.contains("zsh") { return "zsh" }
                if lower.contains("bash") { return "bash" }
                return "sh"
            }()

            items.append(PersistenceItem(
                category: category,
                name: displayName,
                configPath: path,
                executablePath: path,
                isEnabled: true,
                runContext: .login,
                owner: owner,
                riskLevel: riskLevel,
                riskReasons: riskReasons,
                timestamps: timestamps,
                rawMetadata: [
                    "ShellType": .string(shellType),
                    "Scope": .string(isSystem ? "system" : "user")
                ]
            ))
        }

        return items
    }

    // MARK: - Stock Profile Detection

    /// Returns `true` when the file content is a stock/default shell profile
    /// that hasn't been meaningfully modified by the user.
    ///
    /// A profile is considered "stock" when every non-blank line is either a
    /// comment or matches a known default shell statement (prompt assignment,
    /// shopt, setopt, HISTSIZE, bindkey, sourcing the TERM_PROGRAM companion
    /// file, path_helper, etc.).  If any line contains something outside these
    /// defaults it's been customised and we should report it.
    private static func isStockProfile(_ content: String) -> Bool {
        let lines = content.components(separatedBy: .newlines)

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            // Blank lines and comments are always stock.
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }

            // Accept known macOS default statements.
            if Self.isKnownDefaultLine(trimmed) { continue }

            // Anything else means the profile has been customised.
            return false
        }

        return true
    }

    /// Matches individual lines that appear in the stock macOS
    /// `/etc/zshrc`, `/etc/bashrc`, `/etc/profile`, and `/etc/zprofile`.
    private static func isKnownDefaultLine(_ line: String) -> Bool {
        // Common patterns across stock macOS shell profiles.
        let stockPatterns: [String] = [
            // /etc/profile
            "if \\[ -x /usr/libexec/path_helper \\]",
            "eval `/usr/libexec/path_helper",
            "if \\[ \"\\$\\{BASH-no\\}\" != \"no\" \\]",
            "\\[ -r /etc/bashrc \\] && \\. /etc/bashrc",
            // /etc/bashrc
            "if \\[ -z \"\\$PS1\" \\]",
            "return",
            "PS1=",
            "shopt -s checkwinsize",
            "\\[ -r \"/etc/bashrc_\\$TERM_PROGRAM\" \\]",
            // /etc/zshrc & /etc/zprofile
            "if \\[\\[ ",             // if [[ … ]] patterns (combining chars, locale, zkbd)
            "setopt ",
            "disable log",
            "HISTFILE=",
            "HISTSIZE=",
            "SAVEHIST=",
            "source ",
            "typeset ",
            "\\[\\[ -n ",            // [[ -n … ]] key binding tests
            "\\[\\[ -r ",            // [[ -r … ]] file existence checks
            "bindkey ",
            "key\\[",               // key[Delete]= etc.
            "fi",
            "else",
            "then",
            "done",
            "esac",
            "\\[ -r \"/etc/zshrc_\\$TERM_PROGRAM\" \\]",
            "if \\[ -z \"\\$LANG\" \\]",
            "export LANG=",
        ]

        for pattern in stockPatterns {
            if line.range(of: "^\\s*" + pattern, options: .regularExpression) != nil {
                return true
            }
        }
        return false
    }
}
