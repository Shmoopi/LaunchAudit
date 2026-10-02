import Foundation

/// Guarded file reads for untrusted paths.
///
/// Every scanner reads files in locations the audited user can write. Plain
/// `Data(contentsOf:)` / `String(contentsOfFile:)` on such a path is unsafe in
/// three ways:
///
/// 1. **It follows symlinks.** Under `sudo launchaudit scan` that turns any
///    user-writable path in the scan set into an arbitrary root-read primitive —
///    point `~/.zshrc` at a root-only file and its contents land in the report.
/// 2. **It blocks forever on a FIFO or character device.** `mkfifo ~/.zshrc` and
///    the scan never finishes: an attacker who can write one file in `$HOME`
///    permanently disables the auditor, which is far cheaper than evading its
///    detection logic.
/// 3. **It is unbounded.** A multi-gigabyte `manifest.json` is read entirely
///    into memory.
///
/// `SafeRead` refuses anything that is not a regular file, caps the read size, and
/// refuses to follow a symlink that a lower-privileged user could have planted
/// while the process is running as root.
///
/// Deliberately dependency-free: this file is compiled into the privileged helper
/// as well as the app, and the helper's target deliberately contains as little
/// code as possible.
public enum SafeRead {

    /// Default ceiling for a configuration file. Shell profiles, plists and
    /// extension manifests are kilobytes; anything past this is not config.
    public static let defaultMaxBytes = 8 * 1024 * 1024

    public enum Failure: Error, LocalizedError {
        case cannotOpen(path: String, errno: Int32)
        case notRegularFile(path: String)
        case tooLarge(path: String, size: Int)
        case unsafeSymlink(path: String)

        public var errorDescription: String? {
            switch self {
            case .cannotOpen(let path, let code):
                if code == EMLINK || code == ELOOP {
                    return "Refused to follow symlink at \(path)"
                }
                return "Cannot open \(path): \(String(cString: strerror(code)))"
            case .notRegularFile(let path):
                return "Refused to read \(path): not a regular file"
            case .tooLarge(let path, let size):
                return "Refused to read \(path): \(size) bytes exceeds the limit"
            case .unsafeSymlink(let path):
                return "Refused to follow a user-writable symlink while running as "
                    + "root: \(path)"
            }
        }

        /// True when the failure was a permissions problem, so callers can
        /// surface "needs privileges" rather than a generic error.
        public var isPermissionDenied: Bool {
            if case .cannotOpen(_, let code) = self { return code == EACCES || code == EPERM }
            return false
        }
    }

    /// Read a regular file, refusing special files, oversized input, and symlinks
    /// that could be redirecting a privileged read.
    ///
    /// Symlinks are **followed** by default. Refusing them outright is too blunt:
    /// macOS itself ships `/System/Library/LaunchAgents/*.plist` as symlinks into
    /// the Cryptex volume, and third-party installers use them too, so a blanket
    /// refusal silently drops real persistence items — the same false-negative
    /// class this whole file exists to prevent.
    ///
    /// What is actually dangerous is narrower: a symlink **the audited user can
    /// replace**, followed by a scan running as root, pointing at a file that user
    /// could not otherwise read. That case is refused; ordinary system symlinks are
    /// not.
    public static func data(
        atPath path: String,
        maxBytes: Int = defaultMaxBytes
    ) throws -> Data {
        var linkInfo = stat()
        if getuid() == 0,
           lstat(path, &linkInfo) == 0,
           (linkInfo.st_mode & S_IFMT) == S_IFLNK,
           isAttackerControlledLocation(path) {
            throw Failure.unsafeSymlink(path: path)
        }

        // O_NONBLOCK: a FIFO opens immediately instead of blocking for a writer.
        let fd = open(path, O_RDONLY | O_NONBLOCK)
        guard fd >= 0 else { throw Failure.cannotOpen(path: path, errno: errno) }
        defer { close(fd) }

        var st = stat()
        guard fstat(fd, &st) == 0 else {
            throw Failure.cannotOpen(path: path, errno: errno)
        }
        // Regular files only — no FIFOs, devices, sockets or directories.
        guard (st.st_mode & S_IFMT) == S_IFREG else {
            throw Failure.notRegularFile(path: path)
        }
        let size = Int(st.st_size)
        guard size <= maxBytes else {
            throw Failure.tooLarge(path: path, size: size)
        }

        // Now that it is known to be a regular file, blocking reads are safe.
        let flags = fcntl(fd, F_GETFL)
        if flags >= 0 { _ = fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) }

        guard size > 0 else { return Data() }
        var buffer = Data(count: size)
        let bytesRead: Int = buffer.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return -1 }
            var total = 0
            while total < size {
                let n = read(fd, base.advanced(by: total), size - total)
                if n > 0 { total += n } else { break }
            }
            return total
        }
        guard bytesRead >= 0 else { throw Failure.cannotOpen(path: path, errno: errno) }
        return bytesRead == size ? buffer : buffer.prefix(bytesRead)
    }

    /// Read a regular file as UTF-8 text, falling back to a lossy decode so a
    /// config file with stray bytes is still analyzed rather than skipped.
    public static func text(
        atPath path: String,
        maxBytes: Int = defaultMaxBytes
    ) throws -> String {
        let raw = try data(atPath: path, maxBytes: maxBytes)
        if let utf8 = String(data: raw, encoding: .utf8) { return utf8 }
        return String(decoding: raw, as: UTF8.self)
    }

    /// Whether a path sits somewhere a non-root user could have planted it.
    ///
    /// Anything inside a home directory or a world-writable directory qualifies.
    /// Apple-owned, SIP-protected locations do not — macOS ships symlinks there
    /// itself, and an unprivileged user cannot create them.
    private static func isAttackerControlledLocation(_ path: String) -> Bool {
        let appleOwned = ["/System/", "/Library/Apple/"]
        if appleOwned.contains(where: { path.hasPrefix($0) }) { return false }

        if path.hasPrefix("/Users/") { return true }

        let worldWritable = [
            "/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/",
            "/Users/Shared/", "/private/var/folders/", "/var/folders/",
        ]
        if worldWritable.contains(where: { path.hasPrefix($0) }) { return true }

        // Otherwise consult the containing directory's mode bits.
        let directory = (path as NSString).deletingLastPathComponent
        var st = stat()
        guard !directory.isEmpty, stat(directory, &st) == 0 else { return false }
        return (st.st_mode & S_IWOTH) != 0
    }

    /// Byte size of a regular file without reading it.
    public static func size(atPath path: String) -> Int? {
        var st = stat()
        guard lstat(path, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { return nil }
        return Int(st.st_size)
    }
}
