import Foundation

/// LaunchAudit Privileged Helper Tool
///
/// This helper runs as a launchd daemon with root privileges.
/// It provides XPC services to the main LaunchAudit app for reading
/// system paths that require elevated permissions.
///
/// Security: All file access is restricted to a hardcoded allowlist
/// of known persistence mechanism directories.

let delegate = HelperDelegate()
let listener = NSXPCListener(machServiceName: HelperConstants.machServiceName)
listener.delegate = delegate
listener.resume()

RunLoop.current.run()
