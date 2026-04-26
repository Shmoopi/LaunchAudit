import XCTest
@testable import LaunchAudit

/// Locks in the cross-file consistency that SMAppService and NSXPCConnection
/// require: the helper's plist filename, Label, MachServices key, app
/// SMAuthorizedClients reference, and the Swift constants in
/// `HelperConstants` must all line up.  When they don't, the daemon never
/// registers and macOS never prompts the user — silently broken.
final class HelperIdentifierTests: XCTestCase {

    /// Single source of truth used by all assertions in this file.
    /// If you change the helper's bundle identifier, change this — every
    /// other file should already match.
    private let expectedHelperBundleID = "net.shmoopi.launchaudit.helper"
    private let expectedAppBundleID = "net.shmoopi.launchaudit"

    // MARK: - Swift constants

    func testHelperConstantsMatchExpectedBundleID() {
        XCTAssertEqual(HelperConstants.machServiceName, expectedHelperBundleID,
            "HelperConstants.machServiceName drives the NSXPCConnection on the app side.")
        XCTAssertEqual(HelperConstants.helperBundleID, expectedHelperBundleID,
            "HelperConstants.helperBundleID identifies the helper for SMAppService.")
    }

    // MARK: - Helper launchd plist (the file SMAppService registers)

    func testHelperLaunchdPlistMatchesExpectedIdentifier() throws {
        let plistURL = sourcePathFor(
            "LaunchAuditHelper/\(expectedHelperBundleID).plist"
        )
        let data = try Data(contentsOf: plistURL)
        let plist = try PropertyListSerialization.propertyList(
            from: data, format: nil
        ) as? [String: Any]
        let unwrapped = try XCTUnwrap(plist)

        XCTAssertEqual(unwrapped["Label"] as? String, expectedHelperBundleID,
            "launchd Label must equal the bundle identifier so SMAppService can register the daemon.")

        let machServices = try XCTUnwrap(unwrapped["MachServices"] as? [String: Any])
        XCTAssertNotNil(machServices[HelperConstants.machServiceName],
            "MachServices must expose the same Mach name the app's NSXPCConnection requests.")

        // SMAppService daemons reference the embedded binary via BundleProgram
        // (a path relative to the app bundle root). The legacy ProgramArguments
        // /Library/PrivilegedHelperTools/... pattern was for SMJobBless.
        let bundleProgram = try XCTUnwrap(unwrapped["BundleProgram"] as? String)
        XCTAssertEqual(bundleProgram,
            "Contents/MacOS/\(expectedHelperBundleID)",
            "BundleProgram must point at the embedded helper binary path.")
    }

    // MARK: - Helper Info.plist (embedded in the binary)

    func testHelperInfoPlistMatchesExpectedIdentifier() throws {
        let url = sourcePathFor("LaunchAuditHelper/Info.plist")
        let data = try Data(contentsOf: url)
        let plist = try PropertyListSerialization.propertyList(
            from: data, format: nil
        ) as? [String: Any]
        let unwrapped = try XCTUnwrap(plist)

        XCTAssertEqual(unwrapped["CFBundleIdentifier"] as? String, expectedHelperBundleID,
            "Helper Info.plist CFBundleIdentifier must match the launchd Label.")

        let authClients = try XCTUnwrap(unwrapped["SMAuthorizedClients"] as? [String])
        let appClause = "identifier \"\(expectedAppBundleID)\""
        XCTAssertTrue(authClients.contains { $0.contains(appClause) },
            "SMAuthorizedClients must authorize the app's bundle identifier.")
    }

    // MARK: - Helpers

    /// Walk up from this test file to the repo root, then resolve a path
    /// relative to it.  Avoids hard-coding absolute paths or test-bundle
    /// resource embedding.
    private func sourcePathFor(_ relative: String) -> URL {
        // #file points at this test file; repo root is two levels up
        // (LaunchAuditTests/CoordinationTests/HelperIdentifierTests.swift).
        let thisFile = URL(fileURLWithPath: #file)
        let repoRoot = thisFile
            .deletingLastPathComponent() // CoordinationTests
            .deletingLastPathComponent() // LaunchAuditTests
            .deletingLastPathComponent() // repo root
        return repoRoot.appendingPathComponent(relative)
    }
}
