import Foundation

/// XPC protocol for the privileged helper tool.
/// The helper runs as root and provides access to restricted system paths
/// and privileged commands that the main app cannot execute as a regular user.
/// World-readable paths (e.g. /Library/LaunchDaemons, /etc/pam.d) are read
/// directly by the main app without privilege escalation.
@objc public protocol LaunchAuditHelperProtocol {

    /// Read all plist files in a directory and return their contents.
    func readPlistFiles(
        inDirectory path: String,
        reply: @escaping ([Data]?, String?) -> Void
    )

    /// Run sfltool dumpbtm and return the output.
    func dumpBTM(
        reply: @escaping (String?, String?) -> Void
    )

    /// Run kmutil showloaded and return the output.
    func listLoadedKexts(
        reply: @escaping (String?, String?) -> Void
    )

    /// Run profiles list and return the output.
    func listConfigurationProfiles(
        reply: @escaping (String?, String?) -> Void
    )

    /// Check launchd status for a specific label.
    func checkLaunchdStatus(
        label: String,
        domain: String,
        reply: @escaping (String?, String?) -> Void
    )

    /// Read the contents of a file at a specific (allowlisted) path.
    func readFileContents(
        atPath path: String,
        reply: @escaping (Data?, String?) -> Void
    )
}

/// Shared constants for the XPC connection.
public enum HelperConstants {
    public static let machServiceName = "net.shmoopi.launchaudit.helper"
    public static let helperBundleID = "net.shmoopi.launchaudit.helper"
    public static let appBundleID = "net.shmoopi.launchaudit"

    /// Directories the helper is allowed to read from.
    /// Only includes paths that require elevated privileges.
    /// World-readable paths (/Library/LaunchDaemons, /Library/LaunchAgents,
    /// /Library/Extensions, /etc/pam.d, etc.) are read directly by the
    /// main app without privilege escalation.
    public static let allowedPaths: Set<String> = [
        "/private/var/db/emondClients",
        "/private/var/db/ConfigurationProfiles",
        "/private/var/db/com.apple.backgroundtaskmanagement",
        "/private/var/at",
        "/private/var/db/com.apple.xpc.launchd",
        "/private/var/root/Library/Preferences",
    ]

    /// Check whether a path is inside an allowed directory.
    ///
    /// Two defects were fixed here.
    ///
    /// 1. `NSString.standardizingPath` **strips a leading `/private`** whenever the
    ///    result still resolves, so `/private/var/at/jobs` became `/var/at/jobs`,
    ///    which matched none of the entries — the `at`-jobs read silently failed
    ///    with "not in allowlist". Worse, the behaviour was existence-dependent, so
    ///    the same logical path could pass or fail depending on whether the file
    ///    happened to exist.
    /// 2. `hasPrefix` has no component boundary, so `/private/var/attacker` matched
    ///    the `/private/var/at` entry.
    ///
    /// Both are addressed by canonicalizing with `realpath(3)` — which resolves
    /// symlinks for real, rather than removing `..` lexically and leaving a
    /// symlinked intermediate component free to escape — and then comparing whole
    /// path components.
    public static func isPathAllowed(_ path: String) -> Bool {
        // Absolute paths only.
        guard path.hasPrefix("/") else { return false }

        // Lexical containment check first. This is deterministic and does not depend
        // on the path existing or on the caller's ability to stat it — the helper
        // must give the same answer either way.
        guard isLexicallyInsideAllowedDirectory(normalize(path)) else { return false }

        // Then, if the path exists, confirm that where it *actually* resolves to is
        // still inside an allowed directory. This is what stops a symlink planted
        // inside an allowed directory from widening the boundary.
        guard let resolved = realpath(path, nil) else {
            // Not present yet; the lexical check above is the answer.
            return true
        }
        defer { free(resolved) }
        return isLexicallyInsideAllowedDirectory(normalize(String(cString: resolved)))
    }

    private static func isLexicallyInsideAllowedDirectory(_ candidate: String) -> Bool {
        for directory in allowedPaths {
            let normalized = normalize(directory)
            if candidate == normalized { return true }
            // Require a component boundary: `/private/var/attacker` must not match
            // the `/private/var/at` entry.
            if candidate.hasPrefix(normalized + "/") { return true }
        }
        return false
    }

    /// Canonicalize a path textually: resolve `.` and `..`, collapse duplicate
    /// separators, and spell the firmlinked system directories one way.
    ///
    /// `NSString.standardizingPath` is deliberately not used. It strips a leading
    /// `/private` whenever the result still resolves, which silently moved
    /// `/private/var/at/jobs` outside the allowlist — and it did so only when the
    /// path happened to exist, making the check's behaviour depend on filesystem
    /// state.
    static func normalize(_ path: String) -> String {
        var components: [String] = []
        for component in path.components(separatedBy: "/") {
            switch component {
            case "", ".":
                continue
            case "..":
                if !components.isEmpty { components.removeLast() }
            default:
                components.append(component)
            }
        }

        var result = "/" + components.joined(separator: "/")

        // `/var`, `/etc` and `/tmp` are symlinks into `/private`. Spell them the
        // long way so both forms compare equal.
        for short in ["var", "etc", "tmp"] {
            if result == "/\(short)" { return "/private/\(short)" }
            if result.hasPrefix("/\(short)/") {
                result = "/private" + result
                break
            }
        }
        return result
    }
}
