import Foundation
import Security
import os

private let log = Logger(subsystem: HelperConstants.helperBundleID, category: "xpc")

/// NSXPCListener delegate that authenticates incoming connections.
///
/// # Why this matters
///
/// This helper runs as **root** and publishes a Mach service in the system
/// bootstrap namespace, so any non-sandboxed local process can look it up and
/// connect. The previous implementation returned `true` unconditionally — not even
/// a PID check — which handed every local process a root-privileged proxy able to
/// dump the Background Task Management database, read MDM profile payloads and
/// introspect launchd. That is a local privilege escalation and a TCC bypass: a
/// process with no privacy grants at all could reach TCC-protected data through a
/// root daemon that never asked who was calling.
///
/// `SMAuthorizedClients` in Info.plist does **not** cover this. It is an
/// `SMJobBless` key; the helper is registered with `SMAppService.daemon(plistName:)`,
/// which does not read it. The listener delegate is the only control that exists.
final class HelperDelegate: NSObject, NSXPCListenerDelegate, @unchecked Sendable {

    /// Serial queue guarding the idle-exit timer.
    private let queue = DispatchQueue(label: "\(HelperConstants.helperBundleID).delegate")
    private var activeConnections = 0
    private var idleTimer: DispatchSourceTimer?

    /// The helper exits after this long with no connections.
    ///
    /// Without it the daemon stayed resident until reboot, while the in-app banner
    /// told users it "only runs while LaunchAudit is open". launchd will start it
    /// again on demand, so exiting costs nothing.
    private let idleTimeout: TimeInterval = 30

    override init() {
        super.init()
        queue.async { [weak self] in self?.scheduleIdleExit() }
    }

    func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection newConnection: NSXPCConnection
    ) -> Bool {
        guard let requirement = Self.clientRequirement else {
            // Fail closed. If the helper cannot establish its own signing identity
            // it cannot describe a trustworthy client either, so it refuses
            // everything rather than accepting anyone.
            log.error("Refusing connection: helper has no usable code-signing identity")
            return false
        }

        // Kernel-enforced and race-free (macOS 13+): the connection is invalidated
        // if the peer does not satisfy the requirement, and the check is performed
        // against the peer's audit token rather than its PID. Never compare
        // `processIdentifier` directly — PIDs are reusable, so a PID check is a
        // time-of-check/time-of-use bug by construction.
        newConnection.setCodeSigningRequirement(requirement)

        newConnection.exportedInterface = NSXPCInterface(with: LaunchAuditHelperProtocol.self)
        newConnection.exportedObject = HelperService()

        queue.async { [weak self] in
            guard let self else { return }
            self.activeConnections += 1
            self.idleTimer?.cancel()
            self.idleTimer = nil
        }

        let onClose: @Sendable () -> Void = { [weak self] in
            guard let self else { return }
            self.queue.async {
                self.activeConnections = max(0, self.activeConnections - 1)
                if self.activeConnections == 0 { self.scheduleIdleExit() }
            }
        }
        newConnection.invalidationHandler = onClose
        newConnection.interruptionHandler = onClose

        newConnection.resume()
        return true
    }

    /// Exit once nothing has been connected for `idleTimeout`.
    private func scheduleIdleExit() {
        idleTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + idleTimeout)
        timer.setEventHandler {
            log.info("Exiting after idle timeout")
            exit(0)
        }
        idleTimer = timer
        timer.resume()
    }

    /// The code requirement a client must satisfy: the LaunchAudit app, signed by
    /// the same team that signed this helper.
    ///
    /// The team identifier is read from the helper's own signature at runtime rather
    /// than hardcoded, so the requirement stays correct across signing identities
    /// and cannot drift out of sync with the build.
    ///
    /// Note that pinning the bundle identifier alone is not enough: a requirement of
    /// `identifier "net.shmoopi.launchaudit" and anchor apple generic` is satisfied
    /// by *any* Developer ID-signed binary that declares that identifier, i.e. by
    /// anyone with an Apple developer account. The leaf `subject.OU` pin is what
    /// makes it specific to us.
    static let clientRequirement: String? = {
        guard let teamID = ownTeamIdentifier() else { return nil }
        // `setCodeSigningRequirement` raises for a malformed requirement string, so
        // only accept a team identifier of the documented shape before interpolating.
        guard teamID.range(of: #"^[A-Z0-9]{6,12}$"#, options: .regularExpression) != nil else {
            log.error("Refusing to build a requirement from an unexpected team identifier")
            return nil
        }
        return """
        identifier "\(HelperConstants.appBundleID)" \
        and anchor apple generic \
        and certificate leaf[subject.OU] = "\(teamID)"
        """
    }()

    private static func ownTeamIdentifier() -> String? {
        var code: SecCode?
        guard SecCodeCopySelf(SecCSFlags(), &code) == errSecSuccess, let code else { return nil }

        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, SecCSFlags(), &staticCode) == errSecSuccess,
              let staticCode else { return nil }

        var infoRef: CFDictionary?
        guard SecCodeCopySigningInformation(
            staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &infoRef
        ) == errSecSuccess,
              let info = infoRef as? [String: Any] else { return nil }

        // Ad-hoc and unsigned builds have no team identifier. Returning nil here is
        // what makes the listener fail closed for a development build.
        guard let teamID = info[kSecCodeInfoTeamIdentifier as String] as? String,
              !teamID.isEmpty else {
            return nil
        }
        return teamID
    }
}

/// Implementation of the XPC helper service.
final class HelperService: NSObject, LaunchAuditHelperProtocol {

    /// Serializes subprocess work so a burst of connections cannot fork an
    /// unbounded number of root processes. An actor rather than a
    /// `DispatchSemaphore`, which is unsafe to block on from an async context.
    private static let gate = CommandGate()

    func readPlistFiles(inDirectory path: String, reply: @escaping ([Data]?, String?) -> Void) {
        guard HelperConstants.isPathAllowed(path) else {
            reply(nil, "Path not in allowlist: \(path)")
            return
        }

        let fm = FileManager.default
        guard let files = try? fm.contentsOfDirectory(atPath: path) else {
            reply(nil, "Cannot read directory: \(path)")
            return
        }

        var plistData: [Data] = []
        for file in files where file.hasSuffix(".plist") {
            let fullPath = (path as NSString).appendingPathComponent(file)
            // Re-validate the joined path, and read through SafeRead so a symlink
            // planted inside an allowed directory cannot redirect a root read.
            guard HelperConstants.isPathAllowed(fullPath) else { continue }
            if let data = try? SafeRead.data(atPath: fullPath) {
                plistData.append(data)
            }
        }

        reply(plistData, nil)
    }

    func dumpBTM(reply: @escaping (String?, String?) -> Void) {
        runCommand("/usr/bin/sfltool", arguments: ["dumpbtm"], timeout: 20, reply: reply)
    }

    func listLoadedKexts(reply: @escaping (String?, String?) -> Void) {
        runCommand("/usr/bin/kmutil", arguments: ["showloaded", "--show", "loaded"],
                   timeout: 20, reply: reply)
    }

    func listConfigurationProfiles(reply: @escaping (String?, String?) -> Void) {
        runCommand("/usr/bin/profiles", arguments: ["list", "-output", "stdout-xml"],
                   timeout: 20, reply: reply)
    }

    func checkLaunchdStatus(
        label: String,
        domain: String,
        reply: @escaping (String?, String?) -> Void
    ) {
        // Validate against an allowlist rather than stripping characters.
        //
        // The previous code removed `;`, `&` and `|` and commented that this
        // "prevents injection". It did not prevent anything: `Process(arguments:)`
        // never invokes a shell, so those characters were never dangerous — and the
        // comment asserted a protection that did not exist, which is worse than no
        // comment, because the next maintainer would trust it.
        let labelPattern = #"^[A-Za-z0-9][A-Za-z0-9._\-]{0,255}$"#
        guard label.range(of: labelPattern, options: .regularExpression) != nil else {
            reply(nil, "Invalid launchd label")
            return
        }
        let domainPattern = #"^(system|user/[0-9]{1,10}|gui/[0-9]{1,10}|pid/[0-9]{1,10})$"#
        guard domain.range(of: domainPattern, options: .regularExpression) != nil else {
            reply(nil, "Invalid launchd domain")
            return
        }

        runCommand("/bin/launchctl", arguments: ["print", "\(domain)/\(label)"],
                   timeout: 10, reply: reply)
    }

    func readFileContents(atPath path: String, reply: @escaping (Data?, String?) -> Void) {
        guard HelperConstants.isPathAllowed(path) else {
            reply(nil, "Path not in allowlist: \(path)")
            return
        }

        do {
            reply(try SafeRead.data(atPath: path), nil)
        } catch {
            reply(nil, error.localizedDescription)
        }
    }

    // MARK: - Private

    /// Run a command and reply with its stdout.
    ///
    /// Delegates to the shared `ProcessRunner` instead of re-implementing process
    /// handling. The previous local implementation called `waitUntilExit()` and
    /// *then* `readDataToEndOfFile()`, which is the classic pipe deadlock: once the
    /// child fills the ~64KB pipe buffer it blocks on write while the parent blocks
    /// in wait, and the reply block is never invoked. Both `sfltool dumpbtm` and
    /// `kmutil showloaded` exceed 64KB on a normal Mac, and there was no timeout —
    /// so a single call could wedge the root daemon until reboot.
    private func runCommand(
        _ executable: String,
        arguments: [String],
        timeout: TimeInterval,
        reply: @escaping (String?, String?) -> Void
    ) {
        // The reply block must fire exactly once on every path.
        let replied = ReplyGuard()

        Task {
            do {
                let output = try await Self.gate.run(
                    executable, arguments: arguments, timeout: timeout
                )
                if replied.claim() { reply(output, nil) }
            } catch {
                if replied.claim() { reply(nil, error.localizedDescription) }
            }
        }
    }
}

/// Serializes command execution inside the helper.
private actor CommandGate {
    func run(
        _ executable: String,
        arguments: [String],
        timeout: TimeInterval
    ) async throws -> String {
        try await ProcessRunner.shared.run(
            executable, arguments: arguments, timeout: timeout
        )
    }
}

/// One-shot guard so a reply block cannot be invoked twice (which raises) or
/// dropped (which leaks the client's continuation).
private final class ReplyGuard: @unchecked Sendable {
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
