import Foundation

/// Process-wide scan configuration, published by `ScanCoordinator` before a scan
/// and read by individual scanners.
///
/// Replaces the `LAUNCHAUDIT_HEADLESS` environment variable, which was read from
/// three unrelated files, could not be set by a test, and coupled scanner
/// behavior to how the process happened to be launched.
public final class ScanEnvironment: @unchecked Sendable {

    public static let shared = ScanEnvironment()

    private let lock = NSLock()
    private var _avoidInteractivePrompts = false

    public init() {}

    /// When true, scanners must not invoke anything that can raise a GUI consent
    /// dialog — Apple Events to System Events being the main offender.
    public var avoidInteractivePrompts: Bool {
        get {
            lock.lock()
            defer { lock.unlock() }
            return _avoidInteractivePrompts
        }
        set {
            lock.lock()
            _avoidInteractivePrompts = newValue
            lock.unlock()
        }
    }

    public func apply(_ options: ScanOptions) {
        avoidInteractivePrompts = options.avoidInteractivePrompts
    }
}
