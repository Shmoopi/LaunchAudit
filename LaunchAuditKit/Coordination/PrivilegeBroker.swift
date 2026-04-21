import Foundation
import ServiceManagement

/// Manages the connection to the privileged XPC helper.
public actor PrivilegeBroker {
    public static let shared = PrivilegeBroker()

    private var connection: NSXPCConnection?

    private init() {}

    /// Install the privileged helper if not already installed.
    public func installHelperIfNeeded() async throws {
        let service = SMAppService.daemon(plistName: "com.launchaudit.helper.plist")
        let status = service.status

        switch status {
        case .notRegistered, .notFound:
            try service.register()
        case .enabled:
            break // Already installed
        case .requiresApproval:
            // User needs to approve in System Settings > Login Items
            throw PrivilegeBrokerError.requiresApproval
        @unknown default:
            break
        }
    }

    /// Get a proxy to the helper service.
    public func getHelper() throws -> LaunchAuditHelperProtocol {
        if let existing = connection {
            return existing.remoteObjectProxyWithErrorHandler { error in
                print("XPC error: \(error)")
            } as! LaunchAuditHelperProtocol
        }

        let conn = NSXPCConnection(machServiceName: HelperConstants.machServiceName, options: .privileged)
        conn.remoteObjectInterface = NSXPCInterface(with: LaunchAuditHelperProtocol.self)
        conn.resume()
        connection = conn

        return conn.remoteObjectProxyWithErrorHandler { error in
            print("XPC error: \(error)")
        } as! LaunchAuditHelperProtocol
    }

    /// Disconnect from the helper.
    public func disconnect() {
        connection?.invalidate()
        connection = nil
    }
}

public enum PrivilegeBrokerError: Error, LocalizedError {
    case requiresApproval
    case connectionFailed
    case helperNotInstalled

    public var errorDescription: String? {
        switch self {
        case .requiresApproval:
            return "Helper requires approval in System Settings > Login Items & Extensions"
        case .connectionFailed:
            return "Failed to connect to privileged helper"
        case .helperNotInstalled:
            return "Privileged helper is not installed"
        }
    }
}
