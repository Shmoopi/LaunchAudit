import Foundation

/// Resolves whether launchd will actually run a job.
///
/// The `Disabled` key inside a launchd plist has not been authoritative since
/// OS X 10.10. launchd keeps enable/disable state in an override database, and
/// `launchctl enable` / `disable` write there without touching the plist. Reading
/// the plist key alone is wrong in both directions:
///
/// - **Evasion.** Ship a plist with `Disabled = true` so an auditor reports the
///   job as inert, then `launchctl enable` it. It runs; the plist still says
///   disabled.
/// - **Noise.** Jobs the user deliberately disabled are reported as enabled.
///
/// The override database is root-readable only. Without privileges the plist key
/// is the best available answer, so it is used — but a disagreement between the
/// two is surfaced as a finding, because that is exactly the evasion signal.
public final class LaunchdStateResolver: @unchecked Sendable {

    public static let shared = LaunchdStateResolver()

    private let lock = NSLock()
    private var loaded = false
    private var systemOverrides: [String: Bool] = [:]
    private var userOverrides: [String: Bool] = [:]
    /// True when the override database was readable, i.e. the answers are real.
    private var authoritative = false

    private static let databaseDirectory = "/var/db/com.apple.xpc.launchd"

    public init() {}

    public struct State: Sendable {
        public let isEnabled: Bool
        /// Set when the override database contradicts the plist.
        public let note: String?
    }

    /// Whether launchd will run this job.
    public func isEnabled(
        label: String?,
        plistDisabledKey: Bool,
        owner: ItemOwner
    ) -> State {
        let plistSaysEnabled = !plistDisabledKey
        guard let label else { return State(isEnabled: plistSaysEnabled, note: nil) }

        load()

        lock.lock()
        let hasAuthority = authoritative
        let override: Bool? = {
            switch owner {
            case .system: return systemOverrides[label]
            case .user: return userOverrides[label] ?? systemOverrides[label]
            }
        }()
        lock.unlock()

        guard hasAuthority else {
            return State(isEnabled: plistSaysEnabled, note: nil)
        }

        guard let disabledByOverride = override else {
            // No override recorded: the plist key is what launchd used.
            return State(isEnabled: plistSaysEnabled, note: nil)
        }

        let effectivelyEnabled = !disabledByOverride
        guard effectivelyEnabled != plistSaysEnabled else {
            return State(isEnabled: effectivelyEnabled, note: nil)
        }

        // Disagreement. The override wins, and the mismatch is worth reporting.
        let note = effectivelyEnabled
            ? "Plist is marked Disabled but launchd has it enabled — the file "
                + "understates what will run"
            : "Enabled in its plist but disabled via launchctl override"
        return State(isEnabled: effectivelyEnabled, note: note)
    }

    /// True when the override database could be read, so `isEnabled` reflects
    /// launchd's real state rather than the plist key.
    public var hasAuthoritativeState: Bool {
        load()
        lock.lock()
        defer { lock.unlock() }
        return authoritative
    }

    private func load() {
        lock.lock()
        if loaded {
            lock.unlock()
            return
        }
        loaded = true
        lock.unlock()

        let parser = PlistParser()
        var system: [String: Bool] = [:]
        var user: [String: Bool] = [:]
        var readAny = false

        let systemPath = (Self.databaseDirectory as NSString)
            .appendingPathComponent("disabled.plist")
        if let dict = try? parser.parse(at: systemPath) {
            system = dict.compactMapValues { $0 as? Bool }
            readAny = true
        }

        // Per-user overrides live in disabled.<uid>.plist.
        let uid = getuid() == 0 ? Self.consoleUserID() : getuid()
        if let uid {
            let userPath = (Self.databaseDirectory as NSString)
                .appendingPathComponent("disabled.\(uid).plist")
            if let dict = try? parser.parse(at: userPath) {
                user = dict.compactMapValues { $0 as? Bool }
                readAny = true
            }
        }

        lock.lock()
        systemOverrides = system
        userOverrides = user
        authoritative = readAny
        lock.unlock()
    }

    /// UID of the logged-in console user, so a root scan reads the right
    /// per-user override file rather than root's.
    private static func consoleUserID() -> uid_t? {
        var st = stat()
        guard stat("/dev/console", &st) == 0 else { return nil }
        return st.st_uid
    }
}
