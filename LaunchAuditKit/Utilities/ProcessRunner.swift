import Foundation

public actor ProcessRunner {

    public static let shared = ProcessRunner()

    private init() {}

    /// Run a shell command and return its stdout.
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
                let data = stdout.fileHandleForReading.readDataToEndOfFile()
                let output = String(data: data, encoding: .utf8) ?? ""

                if process.terminationStatus == 0 {
                    resumeOnce(with: .success(output))
                } else {
                    let errData = stderr.fileHandleForReading.readDataToEndOfFile()
                    let errOutput = String(data: errData, encoding: .utf8) ?? ""
                    resumeOnce(with: .failure(ProcessRunnerError.nonZeroExit(
                        status: process.terminationStatus,
                        stderr: errOutput
                    )))
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

/// Thread-safe state tracker for one-shot continuation resumption.
private final class ResumeState: @unchecked Sendable {
    private var didResume = false
    private let lock = NSLock()

    /// Attempts to mark as resumed. Returns true if this is the first call, false otherwise.
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
