import XCTest
@testable import LaunchAudit

/// Tests for the privileged helper's only authorization boundary on file reads.
///
/// Two defects are pinned here:
///
/// 1. `NSString.standardizingPath` strips a leading `/private` when the result still
///    resolves, so `/private/var/at/jobs` became `/var/at/jobs` and matched none of
///    the allowlist entries — the read failed with "not in allowlist" and the
///    affected scanner silently reported nothing. The behaviour was also
///    *existence-dependent*, so the same logical path passed or failed depending on
///    whether the file happened to exist.
/// 2. `hasPrefix` with no component boundary let `/private/var/attacker` match the
///    `/private/var/at` entry.
final class HelperPathAllowlistTests: XCTestCase {

    func testAllowsEachDeclaredDirectory() {
        // Every entry must pass its own check. This is the assertion that would
        // have caught the `/private`-stripping bug immediately.
        for directory in HelperConstants.allowedPaths {
            XCTAssertTrue(
                HelperConstants.isPathAllowed(directory),
                "allowlist entry \(directory) does not satisfy its own check"
            )
        }
    }

    func testAllowsFilesInsideAllowedDirectories() {
        XCTAssertTrue(HelperConstants.isPathAllowed("/private/var/at/jobs"))
        XCTAssertTrue(HelperConstants.isPathAllowed("/private/var/at/tabs/root"))
        XCTAssertTrue(
            HelperConstants.isPathAllowed("/private/var/db/com.apple.xpc.launchd/disabled.plist")
        )
    }

    func testAllowsEquivalentPathSpelling() {
        // `/var` is a symlink to `private/var`, so both spellings name the same
        // directory and both must be accepted.
        XCTAssertTrue(HelperConstants.isPathAllowed("/var/at/jobs"))
        XCTAssertTrue(HelperConstants.isPathAllowed("/private/var/at/jobs"))
    }

    func testRejectsSiblingDirectoryWithSharedPrefix() {
        // The component-boundary bug: these share a string prefix with
        // `/private/var/at` but are different directories.
        XCTAssertFalse(HelperConstants.isPathAllowed("/private/var/attacker/evil"))
        XCTAssertFalse(HelperConstants.isPathAllowed("/private/var/atlas"))
        XCTAssertFalse(HelperConstants.isPathAllowed("/var/attacker/payload"))
    }

    func testRejectsTraversalOutOfAllowedDirectory() {
        XCTAssertFalse(
            HelperConstants.isPathAllowed("/private/var/at/../../../etc/master.passwd")
        )
        XCTAssertFalse(HelperConstants.isPathAllowed("/private/var/at/../../db/dslocal"))
    }

    func testRejectsUnrelatedSensitivePaths() {
        for path in ["/etc/master.passwd", "/etc/sudoers", "/Users", "/",
                     "/Library/Keychains/System.keychain"] {
            XCTAssertFalse(
                HelperConstants.isPathAllowed(path),
                "\(path) must not be readable through the helper"
            )
        }
    }

    func testRejectsEmptyAndRelativePaths() {
        XCTAssertFalse(HelperConstants.isPathAllowed(""))
        XCTAssertFalse(HelperConstants.isPathAllowed("var/at/jobs"))
        XCTAssertFalse(HelperConstants.isPathAllowed("../../etc/passwd"))
    }

    func testRejectsSymlinkEscapeFromAllowedDirectory() throws {
        // A symlink planted inside an allowed directory must not widen the
        // boundary. Only runnable as root, since the allowed directories are
        // root-owned; skipped otherwise rather than reported as a pass.
        try XCTSkipUnless(getuid() == 0, "requires root to write into /private/var/at")

        let link = "/private/var/at/launchaudit-test-link"
        try? FileManager.default.removeItem(atPath: link)
        try FileManager.default.createSymbolicLink(
            atPath: link, withDestinationPath: "/etc/master.passwd"
        )
        defer { try? FileManager.default.removeItem(atPath: link) }

        XCTAssertFalse(
            HelperConstants.isPathAllowed(link),
            "realpath must resolve the symlink and reject the escape"
        )
    }
}
