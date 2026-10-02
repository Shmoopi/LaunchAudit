import Foundation
import Darwin

public struct FilelessProcessScanner: PersistenceScanner {
    public let category = PersistenceCategory.filelessProcesses
    /// `/bin/ps -axo` works unprivileged; only `proc_pidpath` on *other* users'
    /// processes needs root. Marking the whole scanner privileged meant an
    /// unprivileged headless scan skipped the tool's highest-severity detector
    /// entirely.
    public let requiresPrivilege = false

    /// Enumerates running processes rather than a fixed set of paths.
    public var scanPaths: [String] { [] }

    public init() {}

    public func scan() async throws -> ScanOutcome {
        // Single ps call covers PID, owner, and command — eliminates the
        // per-PID `ps -o user=` and `lsof -p` calls the previous version made.
        guard let psOutput = await ProcessRunner.shared.tryRun(
            "/bin/ps", arguments: ["-axo", "pid=,user=,comm="]
        ) else {
            return ScanOutcome(errors: [ScanError(
                category: category,
                message: "Could not enumerate running processes via /bin/ps",
                isPermissionDenied: false
            )])
        }

        var items: [PersistenceItem] = []
        var seenPaths = Set<String>()
        let selfPID = ProcessInfo.processInfo.processIdentifier

        for line in psOutput.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { continue }

            // Format: "  PID USER COMMAND"
            let parts = trimmed.split(separator: " ", maxSplits: 2,
                                      omittingEmptySubsequences: true)
            guard parts.count == 3,
                  let pid = Int32(parts[0]) else { continue }

            let user = String(parts[1])
            let comm = String(parts[2])

            // Skip kernel processes and self.
            guard pid > 0, pid != selfPID else { continue }

            // Only check absolute paths — relative names (e.g. "kernel_task")
            // don't refer to user-space binaries.
            guard comm.hasPrefix("/") else { continue }

            // Deduplicate identical paths (e.g. multiple instances of the
            // same deleted binary).
            guard !seenPaths.contains(comm) else { continue }
            seenPaths.insert(comm)

            // The key check: does the binary still exist on disk?
            guard !PathUtilities.exists(comm) else { continue }

            // Native libproc lookup — no subprocess. Returns the process's
            // current executable path (which may differ from `comm` for
            // processes that re-exec'd or whose binary was overwritten).
            let resolvedPath = Self.executablePath(forPID: pid)

            let name = (comm as NSString).lastPathComponent
            let owner: ItemOwner = (user == "root" || user.isEmpty)
                ? .system : .user(user)

            items.append(PersistenceItem(
                category: category,
                name: "\(name) (PID \(pid))",
                label: comm,
                executablePath: resolvedPath ?? comm,
                isEnabled: true,
                runContext: .always,
                owner: owner,
                riskLevel: .high,
                riskReasons: [
                    "Running process has no backing binary on disk",
                    "Binary path: \(comm)"
                ],
                source: .unknown,
                rawMetadata: [
                    "PID": .string("\(pid)"),
                    "OriginalPath": .string(comm),
                    "BinaryMissing": .bool(true)
                ]
            ))
        }

        return ScanOutcome(items: items)
    }

    /// Resolve a PID's executable path via libproc — no subprocess.
    /// Buffer size is `4 * MAXPATHLEN` (PROC_PIDPATHINFO_MAXSIZE) — that
    /// macro isn't bridged into Swift, so the literal lives here.
    private static let pidPathBufferSize = 4 * 1024

    private static func executablePath(forPID pid: Int32) -> String? {
        var buffer = [CChar](repeating: 0, count: pidPathBufferSize)
        let ret = proc_pidpath(pid, &buffer, UInt32(pidPathBufferSize))
        guard ret > 0 else { return nil }
        return String(cString: buffer)
    }
}
