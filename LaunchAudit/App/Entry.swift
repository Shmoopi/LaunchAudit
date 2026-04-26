import Foundation
import SwiftUI

@main
enum AppEntry {
    static func main() {
        // Filter out system/Xcode-injected arguments (e.g., -NSDocumentRevisionsDebugMode YES)
        let cliArgs = filterSystemArguments(Array(CommandLine.arguments.dropFirst()))

        if cliArgs.isEmpty {
            // No CLI arguments → launch the GUI synchronously.
            // SwiftUI's App.main() must be called from a synchronous main()
            // so it can own the run loop via NSApplication.run().
            LaunchAuditApp.main()
            return
        }

        // CLI mode → schedule async work, then keep the main thread alive
        // so @MainActor tasks (ScanCoordinator) can execute.
        let filteredArgv = [CommandLine.arguments[0]] + cliArgs
        Task { @MainActor in
            do {
                let config = try CLIParser.parse(filteredArgv)
                try await CLIRunner.execute(config)
            } catch let error as CLIError {
                Terminal.error(error.message)
                if error.showUsage {
                    Terminal.write("")
                    Terminal.printUsage()
                }
                Self.exitCLI(1)
            } catch {
                Terminal.error(error.localizedDescription)
                Self.exitCLI(1)
            }
            Self.exitCLI(0)
        }
        dispatchMain()
    }

    /// Terminate the CLI process cleanly.
    ///
    /// AppKit (linked via SwiftUI) sends Device Attributes queries (ESC[c)
    /// both during framework init and in `atexit` handlers. The terminal
    /// responds with ESC[?1;2c. If those responses remain in the pty input
    /// buffer when we exit, the shell inherits them as garbled text.
    ///
    /// Two-part fix:
    /// 1. Drain stdin to discard any DA1 responses already in the buffer
    ///    (from framework init at startup).
    /// 2. Use `_exit` instead of `exit` to skip `atexit` handlers that
    ///    would send additional queries during teardown.
    private static func exitCLI(_ code: Int32) -> Never {
        fflush(stdout)
        fflush(stderr)

        // Drain any pending terminal responses from stdin.
        let flags = fcntl(STDIN_FILENO, F_GETFL)
        if flags != -1 {
            _ = fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK)
            var buf = [UInt8](repeating: 0, count: 1024)
            while Darwin.read(STDIN_FILENO, &buf, buf.count) > 0 {}
        }
        tcflush(STDIN_FILENO, TCIFLUSH)

        Darwin._exit(code)
    }

    /// Strip arguments injected by Xcode or the system (e.g., `-NSDocumentRevisionsDebugMode YES`).
    /// These arrive as `-Key value` pairs where Key starts with an uppercase prefix.
    private static func filterSystemArguments(_ args: [String]) -> [String] {
        var filtered: [String] = []
        var i = 0
        while i < args.count {
            let arg = args[i]
            if arg.hasPrefix("-NS") || arg.hasPrefix("-Apple") || arg.hasPrefix("-com.apple.") {
                i += 2 // skip key + value
                continue
            }
            filtered.append(arg)
            i += 1
        }
        return filtered
    }
}
