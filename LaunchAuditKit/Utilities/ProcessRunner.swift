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

            let collectedStdout = OutputCollector()
            let collectedStderr = OutputCollector()
            let drainGroup = DispatchGroup()

            // Timeout
            let timer = DispatchSource.makeTimerSource(queue: .global())
            timer.schedule(deadline: .now() + timeout)
            timer.setEventHandler {
                process.terminate()
                resumeOnce(with: .failure(ProcessRunnerError.timeout))
            }

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
                // Close both ends before bailing out. The drain blocks are started
                // only after a successful launch — dispatching them first meant a
                // launch failure (missing binary, EACCES, sandbox denial) left two
                // libdispatch workers blocked forever in readDataToEndOfFile with
                // the pipe write-ends still open, leaking two threads and two file
                // descriptors per failed call.
                try? stdout.fileHandleForWriting.close()
                try? stdout.fileHandleForReading.close()
                try? stderr.fileHandleForWriting.close()
                try? stderr.fileHandleForReading.close()
                resumeOnce(with: .failure(error))
                return
            }

            // Drain pipes concurrently so the child can never block on full
            // pipe buffers. Each call to readDataToEndOfFile returns when the
            // corresponding write end closes — i.e. when the child exits or
            // closes its stream.
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

            timer.resume()
        }
    }

    /// Run and return nil on error instead of throwing.
    public func tryRun(
        _ executable: String,
        arguments: [String] = [],
        timeout: TimeInterval = 30
    ) async -> String? {
        try? await run(executable, arguments: arguments, timeout: timeout)
    }

    // NOTE: there is deliberately no `shell(_:)` helper.
    //
    // The previous `shell` / `tryShell` pair forwarded to `/bin/sh -c` and had
    // zero call sites anywhere in the project. Every subprocess here uses an
    // absolute executable path and a literal argument array, so no scanned
    // filename or plist value can ever reach a shell. Removing the helpers keeps
    // it that way rather than leaving a loaded gun for a future refactor.
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
