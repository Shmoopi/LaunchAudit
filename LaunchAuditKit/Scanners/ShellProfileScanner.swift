import Foundation

public struct ShellProfileScanner: PersistenceScanner {
    public let category = PersistenceCategory.shellProfiles
    public let requiresPrivilege = false

    /// System-wide shell initialization files.
    private static let systemPaths = [
        "/etc/profile",
        "/etc/bashrc",
        "/etc/bash_profile",
        "/etc/bash.bashrc",
        "/etc/zshrc",
        "/etc/zshenv",
        "/etc/zprofile",
        "/etc/zlogin",
        "/etc/zlogout",
        "/etc/csh.cshrc",
        "/etc/csh.login",
        // Executed on every inbound SSH session.
        "/etc/ssh/sshrc",
    ]

    /// Per-user files, relative to a home directory.
    ///
    /// The original list covered bash and zsh login paths only. Added here:
    /// logout hooks (`.zlogout`, `.bash_logout`), csh/tcsh, fish (including the
    /// auto-sourced `conf.d`), and `~/.ssh/rc`, which runs on every inbound SSH
    /// session.
    private static let userSuffixes = [
        ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile",
        ".zshrc", ".zshenv", ".zprofile", ".zlogin", ".zlogout",
        ".cshrc", ".tcshrc", ".login", ".logout",
        ".config/fish/config.fish",
        ".ssh/rc",
    ]

    /// Directories whose contents are auto-sourced.
    private static let userDirectorySuffixes = [".config/fish/conf.d"]

    /// `path_helper` sources these at login-shell start, so a drop-in that
    /// prepends a writable directory shadows system binaries for every new shell.
    private static let pathHelperDirectories = ["/etc/paths.d", "/etc/manpaths.d"]

    public var scanPaths: [String] {
        var paths = Self.systemPaths
        paths += Self.pathHelperDirectories
        for (_, home) in PathUtilities.scannableHomeDirectories() {
            paths += Self.userSuffixes.map { (home as NSString).appendingPathComponent($0) }
            paths += Self.userDirectorySuffixes.map {
                (home as NSString).appendingPathComponent($0)
            }
        }
        return paths
    }

    public init() {}

    /// Patterns that indicate potentially suspicious content in shell profiles.
    private static let suspiciousPatterns: [(pattern: String, reason: String)] = [
        ("curl.*\\|.*sh", "Downloads and executes remote script"),
        ("wget.*\\|.*sh", "Downloads and executes remote script"),
        ("curl.*\\|.*bash", "Downloads and pipes to bash"),
        ("base64.*(decode|-d\\b)", "Base64 decoding (potential obfuscation)"),
        ("eval.*\\$\\(", "Eval with command substitution"),
        ("eval.*`", "Eval with backtick substitution"),
        ("nc\\s+-l", "Netcat listener (potential reverse shell)"),
        ("ncat.*-e", "Ncat with execute (potential reverse shell)"),
        ("/dev/tcp/", "Bash TCP redirection (potential reverse shell)"),
        ("python.*-c.*import.*socket", "Python socket code (potential reverse shell)"),
        ("DYLD_INSERT_LIBRARIES", "Dynamic library injection variable"),
        ("DYLD_FRAMEWORK_PATH|DYLD_LIBRARY_PATH", "Dynamic loader path override"),
        ("launchctl\\s+(load|bootstrap|enable)", "Loads launchd jobs from a shell profile"),
        ("osascript.*-e", "AppleScript execution from shell"),
        ("openssl.*enc", "OpenSSL encryption/decryption (potential obfuscation)"),
        ("(^|\\s)(source|\\.)\\s+[\"']?(/tmp/|/var/tmp/|/private/tmp/)",
         "Sources a script from a world-writable directory"),
        ("\\bhistory\\s+-c\\b|unset\\s+HISTFILE|HISTFILE=/dev/null",
         "Disables or clears shell history"),
        ("chflags\\s+hidden|\\bxattr\\s+-d\\b", "Hides files or strips quarantine attributes"),
    ]

    /// Pre-compiled regexes — built once at process startup.
    private static let compiledPatterns: [(NSRegularExpression, String)] = {
        suspiciousPatterns.compactMap { entry in
            guard let regex = try? NSRegularExpression(
                pattern: entry.pattern, options: [.caseInsensitive]
            ) else { return nil }
            return (regex, entry.reason)
        }
    }()

    /// Walk file content once per pattern using pre-compiled regexes.
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

    public func scan() async throws -> ScanOutcome {
        var outcome = ScanOutcome()
        var seenCanonicalPaths = Set<String>()

        // `/etc/zshenv` can set ZDOTDIR, which relocates the *entire* zsh user
        // configuration. Without resolving it, the real `.zshrc` is somewhere else
        // and the scanner reads files that are not the ones being executed — a
        // false negative across the whole zsh surface.
        let zdotdir = Self.resolveZDOTDIR()

        var targets: [(path: String, owner: ItemOwner)] = Self.systemPaths.map { ($0, .system) }

        for (user, home) in PathUtilities.scannableHomeDirectories() {
            let configRoot = zdotdir ?? home
            for suffix in Self.userSuffixes {
                // Only the zsh dotfiles honor ZDOTDIR.
                let base = suffix.hasPrefix(".z") ? configRoot : home
                targets.append(((base as NSString).appendingPathComponent(suffix), .user(user)))
            }
            for directory in Self.userDirectorySuffixes {
                let full = (home as NSString).appendingPathComponent(directory)
                let (files, errors) = entries(in: full)
                outcome.errors += errors
                targets += files.map { ($0, .user(user)) }
            }
        }

        for (path, owner) in targets {
            guard PathUtilities.exists(path) else { continue }

            // Resolve symlinks and normalize so the same underlying file is
            // never reported twice (e.g. /etc/zshrc -> /private/etc/zshrc).
            let canonicalPath = (path as NSString).resolvingSymlinksInPath
            guard seenCanonicalPaths.insert(canonicalPath).inserted else { continue }

            let filename = (path as NSString).lastPathComponent
            let isSystem = path.hasPrefix("/etc") || path.hasPrefix("/private/etc")

            // Size is checked before reading rather than after loading the file.
            let byteSize = SafeRead.size(atPath: path)

            let content: String?
            do {
                content = try SafeRead.text(atPath: path, maxBytes: 2 * 1024 * 1024)
            } catch {
                outcome.errors.append(scanError(error, path: path))
                continue
            }

            var riskReasons: [String] = []
            var riskLevel: RiskLevel = .informational

            if let content {
                riskReasons = Self.suspiciousReasons(in: content)
                if !riskReasons.isEmpty { riskLevel = .high }

                // Suspicious content vetoes stock classification. Previously the
                // stock check ran *first* and `continue`d on a match, so a
                // `~/.zshrc` whose only line was `source ~/.payload` was never
                // even turned into an item.
                if riskReasons.isEmpty,
                   isSystem,
                   Self.isStockProfile(content) {
                    continue
                }

                if let byteSize, byteSize > 50_000 {
                    riskReasons.append("Unusually large shell profile (\(byteSize) bytes)")
                    if riskLevel < .medium { riskLevel = .medium }
                }
            }

            let displayName = isSystem ? "\(filename) (system)" : filename

            let shellType: String = {
                let lower = path.lowercased()
                if lower.contains("fish") { return "fish" }
                if lower.contains("zsh") || lower.contains(".z") { return "zsh" }
                if lower.contains("bash") { return "bash" }
                if lower.contains("csh") { return "csh" }
                if lower.contains("ssh") { return "ssh" }
                return "sh"
            }()

            var metadata: [String: PlistValue] = [
                "ShellType": .string(shellType),
                "Scope": .string(isSystem ? "system" : "user"),
            ]
            if let byteSize { metadata["SizeBytes"] = .string("\(byteSize)") }
            if let zdotdir { metadata["ZDOTDIR"] = .string(zdotdir) }

            outcome.items.append(PersistenceItem(
                category: category,
                name: displayName,
                configPath: path,
                executablePath: nil,
                isEnabled: true,
                runContext: .login,
                owner: owner,
                riskLevel: riskLevel,
                riskReasons: riskReasons,
                timestamps: PathUtilities.timestamps(for: path),
                rawMetadata: metadata
            ))
        }

        // path_helper drop-ins.
        for directory in Self.pathHelperDirectories {
            let (files, errors) = entries(in: directory)
            outcome.errors += errors
            for file in files {
                let content = (try? SafeRead.text(atPath: file, maxBytes: 64 * 1024)) ?? ""
                let paths = content.components(separatedBy: .newlines)
                    .map { $0.trimmingCharacters(in: .whitespaces) }
                    .filter { !$0.isEmpty }

                var reasons: [String] = []
                var level: RiskLevel = .informational
                for entry in paths where PathUtilities.isInWorldWritableDirectory(entry)
                    || (PathUtilities.isWritableByNonRoot(entry) && !PathUtilities.isAppleOwnedPath(entry)) {
                    reasons.append("Prepends a user-writable directory to PATH: \(entry)")
                    level = .high
                }

                outcome.items.append(PersistenceItem(
                    category: category,
                    name: "\((directory as NSString).lastPathComponent)/"
                        + (file as NSString).lastPathComponent,
                    configPath: file,
                    isEnabled: true,
                    runContext: .login,
                    owner: .system,
                    riskLevel: level,
                    riskReasons: reasons,
                    timestamps: PathUtilities.timestamps(for: file),
                    rawMetadata: [
                        "Type": .string("path_helper drop-in"),
                        "Entries": .array(paths.map { .string($0) }),
                    ]
                ))
            }
        }

        return outcome
    }

    /// Read ZDOTDIR out of the system zshenv, which runs before any user file.
    static func resolveZDOTDIR() -> String? {
        for candidate in ["/etc/zshenv", "/etc/zprofile"] {
            guard let content = try? SafeRead.text(atPath: candidate, maxBytes: 256 * 1024)
            else { continue }
            for line in content.components(separatedBy: .newlines) {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                guard !trimmed.hasPrefix("#") else { continue }
                guard let range = trimmed.range(of: "ZDOTDIR=") else { continue }
                var value = String(trimmed[range.upperBound...])
                    .trimmingCharacters(in: CharacterSet(charactersIn: "\"' "))
                if let space = value.firstIndex(where: { $0 == " " || $0 == ";" }) {
                    value = String(value[value.startIndex..<space])
                }
                value = value.replacingOccurrences(of: "$HOME", with: PathUtilities.homeDirectory)
                value = PathUtilities.expandTilde(value)
                if !value.isEmpty, PathUtilities.isDirectory(value) { return value }
            }
        }
        return nil
    }

    // MARK: - Stock Profile Detection

    /// Returns `true` when the file content is a stock/default shell profile.
    ///
    /// Applied **only** to files under `/etc`, and only after the suspicious-content
    /// check has come back clean. It used to be applied to user dotfiles too, where
    /// the unanchored patterns below matched far too much: `source /tmp/evil.sh`,
    /// `typeset -x EVIL=1` and even `find / -exec curl …` (the bare `fi` pattern
    /// matches `find`) all classified as stock and were dropped without analysis.
    static func isStockProfile(_ content: String) -> Bool {
        let lines = content.components(separatedBy: .newlines)

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
            if Self.isKnownDefaultLine(trimmed) { continue }
            return false
        }

        return true
    }

    /// Matches individual lines that appear in the stock macOS
    /// `/etc/zshrc`, `/etc/bashrc`, `/etc/profile`, and `/etc/zprofile`.
    ///
    /// Every pattern is anchored at both ends. The previous version anchored only
    /// the start, so generic fragments such as `fi`, `else`, `source ` and
    /// `typeset ` matched arbitrary attacker-supplied lines that merely began the
    /// same way.
    static func isKnownDefaultLine(_ line: String) -> Bool {
        let stockPatterns: [String] = [
            // /etc/profile
            "if \\[ -x /usr/libexec/path_helper \\][;\\s]*(then)?",
            "eval `/usr/libexec/path_helper[^`]*`",
            "eval \"\\$\\(/usr/libexec/path_helper[^\"]*\\)\"",
            "if \\[ \"\\$\\{BASH-no\\}\" != \"no\" \\][;\\s]*(then)?",
            "\\[ -r /etc/bashrc \\] && \\. /etc/bashrc",
            // /etc/bashrc
            "if \\[ -z \"\\$PS1\" \\][;\\s]*(then)?",
            "PS1=.*",
            "shopt -s checkwinsize",
            "\\[ -r \"/etc/bashrc_\\$TERM_PROGRAM\" \\] && \\. \"/etc/bashrc_\\$TERM_PROGRAM\"",
            // /etc/zshrc & /etc/zprofile
            "setopt [A-Za-z_ ]+",
            "unsetopt [A-Za-z_ ]+",
            "disable log",
            "HISTFILE=[^;|&`$]*",
            "HISTSIZE=[0-9]*",
            "SAVEHIST=[0-9]*",
            "bindkey [^;|&`$]*",
            "autoload -Uz? [A-Za-z_ -]+",
            "zstyle [^;|&`$]*",
            // Structural keywords, exact-match only.
            "fi", "else", "then", "done", "esac", "return", "elif", "\\}", "\\{",
            "\\[ -r \"/etc/zshrc_\\$TERM_PROGRAM\" \\] && \\. \"/etc/zshrc_\\$TERM_PROGRAM\"",
            "if \\[ -z \"\\$LANG\" \\][;\\s]*(then)?",
            "export LANG=[A-Za-z0-9_.-]*",
            "export PATH=[A-Za-z0-9_:/.${}\"-]*",
        ]

        for pattern in stockPatterns {
            // Anchored at both ends: the whole line must be stock boilerplate.
            if line.range(of: "^\\s*" + pattern + "\\s*;?\\s*$",
                          options: .regularExpression) != nil {
                return true
            }
        }
        return false
    }
}
