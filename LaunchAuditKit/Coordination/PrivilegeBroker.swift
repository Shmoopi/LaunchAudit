import Foundation
import ServiceManagement

/// Manages the connection to the privileged XPC helper, and exposes the
/// privileged operations as `async` calls.
///
/// The helper used to be registered — asking the user to approve a **root**
/// background daemon — and then never contacted: `getHelper()` had zero call sites
/// anywhere in the project. Privileged scanners instead checked `getuid() == 0`,
/// which is never true in the GUI, so Background Task Management and Configuration
/// Profiles always came back empty while the in-app banner promised the opposite.
/// The wrappers below are what close that gap.
public actor PrivilegeBroker {
    public static let shared = PrivilegeBroker()

    private var connection: NSXPCConnection?

    private init() {}

    // MARK: - Registration

    /// Install the privileged helper if not already installed.
    ///
    /// Returns the status *after* the attempt. `register()` on a fresh install
    /// leaves the daemon in `.requiresApproval`, so the caller has to re-read the
    /// status rather than assume success — otherwise a first-run user is recorded as
    /// `.enabled` while the daemon sits unapproved, and the banner explaining what to
    /// do never appears.
    @discardableResult
    public func installHelperIfNeeded() async throws -> SMAppService.Status {
        let service = SMAppService.daemon(plistName: "net.shmoopi.launchaudit.helper.plist")

        switch service.status {
        case .notRegistered, .notFound:
            try service.register()
        case .enabled:
            return .enabled
        case .requiresApproval:
            throw PrivilegeBrokerError.requiresApproval
        @unknown default:
            break
        }

        // Re-read: registration does not imply approval.
        let status = service.status
        if status == .requiresApproval {
            throw PrivilegeBrokerError.requiresApproval
        }
        return status
    }

    /// Current helper status, without attempting registration.
    public func currentStatus() -> SMAppService.Status {
        SMAppService.daemon(plistName: "net.shmoopi.launchaudit.helper.plist").status
    }

    // MARK: - Connection

    /// Get a proxy to the helper service.
    private func proxy() throws -> LaunchAuditHelperProtocol {
        let conn: NSXPCConnection
        if let existing = connection {
            conn = existing
        } else {
            let new = NSXPCConnection(
                machServiceName: HelperConstants.machServiceName, options: .privileged
            )
            new.remoteObjectInterface = NSXPCInterface(with: LaunchAuditHelperProtocol.self)

            // Drop the cached connection when it dies, so the next call reconnects.
            // Previously the connection was cached forever with no invalidation
            // handler, so once the helper exited every later call failed silently
            // against a dead proxy.
            let clear: @Sendable () -> Void = { [weak self] in
                Task { await self?.clearConnection() }
            }
            new.invalidationHandler = clear
            new.interruptionHandler = clear

            new.resume()
            connection = new
            conn = new
        }

        // `remoteObjectProxyWithErrorHandler`, not the plain proxy.
        //
        // With the plain proxy, a message sent to a helper that is not installed —
        // or that refuses the connection because the client fails the code
        // requirement — fails with no observer at all, so the reply block never
        // runs and the continuation waiting on it hangs forever. That deadlocked
        // the whole scan on any machine without an approved helper.
        //
        // `as?`, not `as!`: a force cast crashed the app when the proxy could not
        // be created.
        let handler = ProxyErrorHandler()
        let proxy = conn.remoteObjectProxyWithErrorHandler { error in
            handler.fail(error)
        }
        guard let remote = proxy as? LaunchAuditHelperProtocol else {
            throw PrivilegeBrokerError.connectionFailed
        }
        currentErrorHandler = handler
        return remote
    }

    /// Receives XPC transport failures for the in-flight call.
    private var currentErrorHandler: ProxyErrorHandler?

    private final class ProxyErrorHandler: @unchecked Sendable {
        private let lock = NSLock()
        private var onFailure: (@Sendable (Error) -> Void)?

        func setHandler(_ handler: @escaping @Sendable (Error) -> Void) {
            lock.lock(); defer { lock.unlock() }
            onFailure = handler
        }

        func fail(_ error: Error) {
            lock.lock()
            let handler = onFailure
            onFailure = nil
            lock.unlock()
            handler?(error)
        }

        func clear() {
            lock.lock(); defer { lock.unlock() }
            onFailure = nil
        }
    }

    private func clearConnection() {
        connection = nil
    }

    /// Disconnect from the helper.
    public func disconnect() {
        connection?.invalidate()
        connection = nil
    }

    // MARK: - Privileged operations

    /// Run `sfltool dumpbtm` as root.
    public func dumpBTM() async throws -> String {
        try await withText { helper, completion in
            helper.dumpBTM(reply: completion)
        }
    }

    /// Run `profiles list -output stdout-xml` as root.
    public func listConfigurationProfiles() async throws -> String {
        try await withText { helper, completion in
            helper.listConfigurationProfiles(reply: completion)
        }
    }

    /// Run `kmutil showloaded` as root.
    public func listLoadedKexts() async throws -> String {
        try await withText { helper, completion in
            helper.listLoadedKexts(reply: completion)
        }
    }

    /// Read a file from one of the helper's allowlisted directories.
    public func readFile(atPath path: String) async throws -> Data {
        try await call { helper, resume in
            helper.readFileContents(atPath: path) { data, errorMessage in
                if let data {
                    resume(.success(data))
                } else {
                    resume(.failure(PrivilegeBrokerError.operationFailed(
                        errorMessage ?? "helper returned no data"
                    )))
                }
            }
        }
    }

    /// Read every plist in one of the helper's allowlisted directories.
    public func readPlists(inDirectory path: String) async throws -> [Data] {
        try await call { helper, resume in
            helper.readPlistFiles(inDirectory: path) { plists, errorMessage in
                if let plists {
                    resume(.success(plists))
                } else {
                    resume(.failure(PrivilegeBrokerError.operationFailed(
                        errorMessage ?? "helper returned no data"
                    )))
                }
            }
        }
    }

    /// Bridge a `(String?, String?) -> Void` helper callback to `async throws`.
    private func withText(
        _ body: @escaping (LaunchAuditHelperProtocol, @escaping (String?, String?) -> Void) -> Void
    ) async throws -> String {
        try await call { helper, resume in
            body(helper) { output, errorMessage in
                if let output, !output.isEmpty {
                    resume(.success(output))
                } else {
                    resume(.failure(PrivilegeBrokerError.operationFailed(
                        errorMessage ?? "helper returned no output"
                    )))
                }
            }
        }
    }

    /// Invoke a helper method and bridge its reply block to `async throws`.
    ///
    /// Three things must all resume exactly one continuation: the reply block, an
    /// XPC transport failure, and a timeout. Without the last two, a helper that is
    /// missing, refuses the connection, or simply never answers would leave the
    /// caller — and with it the whole scan — waiting forever.
    private func call<T: Sendable>(
        timeout: TimeInterval = 25,
        _ body: @escaping (LaunchAuditHelperProtocol, @escaping @Sendable (Result<T, Error>) -> Void) -> Void
    ) async throws -> T {
        let helper = try proxy()
        let handler = currentErrorHandler

        return try await withCheckedThrowingContinuation { continuation in
            let once = ContinuationGuard()
            let resume: @Sendable (Result<T, Error>) -> Void = { result in
                guard once.claim() else { return }
                handler?.clear()
                continuation.resume(with: result)
            }

            handler?.setHandler { error in
                resume(.failure(PrivilegeBrokerError.operationFailed(
                    "helper connection failed: \(error.localizedDescription)"
                )))
            }

            Task {
                try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                resume(.failure(PrivilegeBrokerError.operationFailed(
                    "helper did not respond within \(Int(timeout))s"
                )))
            }

            body(helper, resume)
        }
    }
}

/// One-shot guard for a checked continuation driven by an XPC reply block.
private final class ContinuationGuard: @unchecked Sendable {
    private let lock = NSLock()
    private var used = false

    func claim() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !used else { return false }
        used = true
        return true
    }
}

public enum PrivilegeBrokerError: Error, LocalizedError {
    case requiresApproval
    case connectionFailed
    case helperNotInstalled
    case operationFailed(String)

    public var errorDescription: String? {
        switch self {
        case .requiresApproval:
            return "The LaunchAudit helper needs approval in System Settings → "
                + "General → Login Items & Extensions"
        case .connectionFailed:
            return "Could not connect to the privileged helper"
        case .helperNotInstalled:
            return "The privileged helper is not installed"
        case .operationFailed(let message):
            return message
        }
    }
}

/// Runs a privileged command, preferring whatever route is actually available.
///
/// Scanners call this instead of testing `getuid() == 0` themselves, so a GUI run
/// with an approved helper gets the same coverage a `sudo` run does.
public enum PrivilegedCommand {

    public enum Route: Sendable {
        /// The process is already root; run the tool directly.
        case direct
        /// Ask the root helper.
        case helper
    }

    /// Run `sfltool dumpbtm`, directly when root and via the helper otherwise.
    public static func dumpBTM() async throws -> (output: String, route: Route) {
        if PathUtilities.isRoot {
            let output = try await ProcessRunner.shared.run(
                "/usr/bin/sfltool", arguments: ["dumpbtm"], timeout: 20
            )
            return (output, .direct)
        }
        return (try await PrivilegeBroker.shared.dumpBTM(), .helper)
    }

    /// Run `profiles list`, directly when root and via the helper otherwise.
    public static func listConfigurationProfiles() async throws -> (output: String, route: Route) {
        if PathUtilities.isRoot {
            let output = try await ProcessRunner.shared.run(
                "/usr/bin/profiles",
                arguments: ["list", "-output", "stdout-xml"],
                timeout: 20
            )
            return (output, .direct)
        }
        return (try await PrivilegeBroker.shared.listConfigurationProfiles(), .helper)
    }
}
