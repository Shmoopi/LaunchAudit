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

    /// Directories the helper is allowed to read from.
    /// Only includes paths that require elevated privileges.
    /// World-readable paths (/Library/LaunchDaemons, /Library/LaunchAgents,
    /// /Library/Extensions, /etc/pam.d, etc.) are read directly by the
    /// main app without privilege escalation.
    public static let allowedPaths: Set<String> = [
        "/private/var/db/emondClients",
        "/var/db/ConfigurationProfiles",
        "/private/var/db/com.apple.backgroundtaskmanagement",
        "/private/var/at",
    ]

    /// Check if a path is within an allowed directory.
    public static func isPathAllowed(_ path: String) -> Bool {
        let resolved = (path as NSString).standardizingPath
        return allowedPaths.contains { allowedDir in
            resolved.hasPrefix(allowedDir)
        }
    }
}
