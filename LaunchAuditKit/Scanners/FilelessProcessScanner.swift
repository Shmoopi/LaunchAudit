import Foundation

public struct FilelessProcessScanner: PersistenceScanner {
    public let category = PersistenceCategory.filelessProcesses
    public let requiresPrivilege = true

    public var scanPaths: [String] { [] }

    public init() {}

    public func scan() async throws -> [PersistenceItem] {
        // Get all running processes with their PIDs and executable paths
        guard let psOutput = await ProcessRunner.shared.tryShell(
            "ps -axo pid=,comm= 2>/dev/null"
        ) else {
            return []
        }

        var items: [PersistenceItem] = []
        var seenPaths = Set<String>()

        for line in psOutput.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { continue }

            // Parse "  PID COMMAND" — PID is right-aligned, command follows
            let parts = trimmed.split(separator: " ", maxSplits: 1)
            guard parts.count == 2,
                  let pid = Int(parts[0]) else { continue }

            let comm = String(parts[1])

            // Skip kernel processes (pid 0) and this process
            guard pid > 0, pid != ProcessInfo.processInfo.processIdentifier else { continue }

            // Only check absolute paths — relative names (e.g. "kernel_task")
            // don't refer to user-space binaries
            guard comm.hasPrefix("/") else { continue }

            // Deduplicate — multiple instances of the same deleted binary
            guard !seenPaths.contains(comm) else { continue }
            seenPaths.insert(comm)

            // The key check: does the binary still exist on disk?
            guard !PathUtilities.exists(comm) else { continue }

            // Resolve the actual executable path via /proc or lsof for confirmation
            let procPath = await resolveExecutablePath(pid: pid)

            let name = (comm as NSString).lastPathComponent
            let owner: ItemOwner = await processOwner(pid: pid)

            items.append(PersistenceItem(
                category: category,
                name: "\(name) (PID \(pid))",
                label: comm,
                executablePath: procPath ?? comm,
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

        return items
    }

    /// Try to resolve the actual executable path for a running process.
    private func resolveExecutablePath(pid: Int) async -> String? {
        // Use lsof to find the process executable
        guard let output = await ProcessRunner.shared.tryShell(
            "lsof -p \(pid) -Fn 2>/dev/null | head -5"
        ) else { return nil }

        for line in output.components(separatedBy: "\n") {
            if line.hasPrefix("n") && line.contains("/") {
                return String(line.dropFirst())
            }
        }
        return nil
    }

    /// Determine the owner of a running process.
    private func processOwner(pid: Int) async -> ItemOwner {
        guard let output = await ProcessRunner.shared.tryShell(
            "ps -o user= -p \(pid) 2>/dev/null"
        ) else { return .system }

        let user = output.trimmingCharacters(in: .whitespacesAndNewlines)
        if user == "root" || user.isEmpty {
            return .system
        }
        return .user(user)
    }
}
