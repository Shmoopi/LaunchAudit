import Foundation

public actor ProcessRunner {

    public static let shared = ProcessRunner()

    private init() {}

    /// Run a binary directly and return its stdout.
    ///
    /// Drains stdout/stderr on background queues so the child process never
    /// blocks on a full pipe buffer. macOS pipe buffers are ~64 KB; commands
    /// like `ps -axo` exceed that easily and would deadlock if we waited
    /// until termination to read.
    public func run(
        _ executable: String,
        arguments: [String] = [],
        timeout: TimeInterval = 30
    ) async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: executable)
            process.arguments = arguments

            let stdout = Pipe()
            let stderr = Pipe()
            process.standardOutput = stdout
            process.standardError = stderr

            let resumeState = ResumeState()

            @Sendable func resumeOnce(with result: Result<String, Error>) {
                guard resumeState.tryResume() else { return }
                continuation.resume(with: result)
            }

            // Drain pipes concurrently so the child can never block on full
            // pipe buffers. Each call to readDataToEndOfFile returns when the
            // corresponding write end closes — i.e. when the child exits or
            // closes its stream.
            let collectedStdout = OutputCollector()
            let collectedStderr = OutputCollector()
            let drainGroup = DispatchGroup()

            drainGroup.enter()
            DispatchQueue.global(qos: .userInitiated).async {
                let data = stdout.fileHandleForReading.readDataToEndOfFile()
                collectedStdout.set(data)
                drainGroup.leave()
            }
            drainGroup.enter()
            DispatchQueue.global(qos: .userInitiated).async {
                let data = stderr.fileHandleForReading.readDataToEndOfFile()
                collectedStderr.set(data)
                drainGroup.leave()
            }

            // Timeout
            let timer = DispatchSource.makeTimerSource(queue: .global())
            timer.schedule(deadline: .now() + timeout)
            timer.setEventHandler {
                process.terminate()
                resumeOnce(with: .failure(ProcessRunnerError.timeout))
            }
            timer.resume()

            process.terminationHandler = { _ in
                timer.cancel()
                // Wait for both drains to finish so we have complete output.
                drainGroup.notify(queue: .global()) {
                    let outData = collectedStdout.data
                    let output = String(data: outData, encoding: .utf8) ?? ""

                    if process.terminationStatus == 0 {
                        resumeOnce(with: .success(output))
                    } else {
                        let errData = collectedStderr.data
                        let errOutput = String(data: errData, encoding: .utf8) ?? ""
                        resumeOnce(with: .failure(ProcessRunnerError.nonZeroExit(
                            status: process.terminationStatus,
                            stderr: errOutput
                        )))
                    }
                }
            }

            do {
                try process.run()
            } catch {
                timer.cancel()
                resumeOnce(with: .failure(error))
            }
        }
    }

    /// Run a shell command via /bin/sh -c.
    /// Prefer `run(_:arguments:)` when no shell features are needed —
    /// it skips the /bin/sh fork.
    public func shell(_ command: String, timeout: TimeInterval = 30) async throws -> String {
        try await run("/bin/sh", arguments: ["-c", command], timeout: timeout)
    }

    /// Run and return nil on error instead of throwing.
    public func tryRun(
        _ executable: String,
        arguments: [String] = [],
        timeout: TimeInterval = 30
    ) async -> String? {
        try? await run(executable, arguments: arguments, timeout: timeout)
    }

    /// Run a shell command and return nil on error.
    public func tryShell(_ command: String, timeout: TimeInterval = 30) async -> String? {
        try? await shell(command, timeout: timeout)
    }
}

/// Thread-safe holder for output bytes collected on a background queue.
private final class OutputCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var storage = Data()
    var data: Data {
        lock.lock(); defer { lock.unlock() }
        return storage
    }
    func set(_ value: Data) {
        lock.lock(); defer { lock.unlock() }
        storage = value
    }
}

/// Thread-safe state tracker for one-shot continuation resumption.
private final class ResumeState: @unchecked Sendable {
    private var didResume = false
    private let lock = NSLock()

    func tryResume() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !didResume else { return false }
        didResume = true
        return true
    }
}

public enum ProcessRunnerError: Error, LocalizedError {
    case timeout
    case nonZeroExit(status: Int32, stderr: String)

    public var errorDescription: String? {
        switch self {
        case .timeout:
            return "Process timed out"
        case .nonZeroExit(let status, let stderr):
            return "Process exited with status \(status): \(stderr)"
        }
    }
}
