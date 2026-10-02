import XCTest
@testable import LaunchAudit

/// Tests for the trust layer.
///
/// The key assertions here are the **negative** ones. The previous suite only
/// checked that `/bin/ls` came back Apple-signed, so it could not catch the two
/// defects that mattered: that trust was decided by string-matching a certificate
/// Common Name (forgeable), and that the leaf CN for Apple platform binaries is
/// "macOS Software Signing" rather than "Software Signing" — which made
/// `isAppleSigned` false for every Apple binary on a current system.
final class SigningVerifierTests: XCTestCase {

    private var tempDir: URL!

    override func setUpWithError() throws {
        tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("LaunchAuditTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: tempDir, withIntermediateDirectories: true
        )
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: tempDir)
    }

    // MARK: - Apple platform binaries

    /// A codeless kext has no executable; the bundle itself carries the signature.
    func testCodelessKextBundleIsAppleSigned() throws {
        let path = "/Library/Extensions/AppleMobileDevice.kext"
        guard FileManager.default.fileExists(atPath: path) else {
            throw XCTSkip("AppleMobileDevice.kext is not installed")
        }
        let info = SigningVerifier().verify(path: path)
        XCTAssertTrue(info.isSigned)
        XCTAssertTrue(info.isAppleSigned)
    }

    /// XProtect's bundle uses custom resource omit rules, which strict validation
    /// rejects. It must still come back Apple-signed, not unsigned.
    func testAppleSignatureWithLegacyResourceRulesIsRecognized() throws {
        let path = "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtect"
        guard FileManager.default.fileExists(atPath: path) else {
            throw XCTSkip("XProtect is not installed at \(path)")
        }
        let info = SigningVerifier().verify(path: path)
        XCTAssertTrue(info.isSigned)
        XCTAssertTrue(info.isAppleSigned)
    }

    func testApplePlatformBinariesAreRecognized() {
        let verifier = SigningVerifier()
        // Every one of these is Apple platform code. A subject-string check fails
        // all of them on macOS 15+, so this is the regression test for that bug.
        for path in ["/bin/ls", "/bin/sh", "/usr/bin/python3", "/usr/bin/osascript"] {
            let info = verifier.verify(path: path)
            XCTAssertTrue(info.isSigned, "\(path) should be signed")
            XCTAssertTrue(
                info.isAppleSigned,
                "\(path) must satisfy `anchor apple`. If this fails, trust is being "
                    + "decided from certificate subject strings again."
            )
        }
    }

    func testApplePlatformBinaryIsNotClaimedAdHoc() {
        let info = SigningVerifier().verify(path: "/bin/ls")
        XCTAssertFalse(info.isAdHocSigned, "Apple platform code is not ad-hoc signed")
    }

    // MARK: - Negative cases

    func testMissingFileReturnsUnsigned() {
        let info = SigningVerifier().verify(path: "/nonexistent/path/to/binary")
        XCTAssertFalse(info.isSigned)
        XCTAssertFalse(info.isAppleSigned)
        XCTAssertFalse(info.isNotarized)
    }

    func testUnsignedFileIsNotAppleSigned() throws {
        // A plain file with no signature at all.
        let path = tempDir.appendingPathComponent("payload").path
        try Data("#!/bin/sh\necho hi\n".utf8).write(to: URL(fileURLWithPath: path))

        let info = SigningVerifier().verify(path: path)
        XCTAssertFalse(info.isSigned)
        XCTAssertFalse(info.isAppleSigned)
        XCTAssertFalse(info.isNotarized)
    }

    /// A copy of an Apple binary is no longer validly signed once its contents are
    /// altered, and must not inherit Apple trust.
    func testTamperedCopyOfAppleBinaryLosesAppleTrust() throws {
        let copyPath = tempDir.appendingPathComponent("ls").path
        try FileManager.default.copyItem(atPath: "/bin/ls", toPath: copyPath)

        // Append a byte: the signature no longer covers the file.
        let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: copyPath))
        try handle.seekToEnd()
        try handle.write(contentsOf: Data([0x00]))
        try handle.close()

        let info = SigningVerifier().verify(path: copyPath)
        XCTAssertFalse(
            info.isAppleSigned,
            "A tampered copy of an Apple binary must not report as Apple-signed"
        )
    }

    /// The display-only certificate chain must never be the thing trust rests on.
    func testSigningAuthorityIsPopulatedButNotTrusted() {
        let info = SigningVerifier().verify(path: "/bin/ls")
        XCTAssertFalse(info.signingAuthority.isEmpty, "chain is captured for display")
        // The leaf on current macOS is "macOS Software Signing" — the exact string
        // the old hardcoded comparison did not match.
        XCTAssertTrue(
            info.signingAuthority[0].contains("Software Signing"),
            "unexpected leaf subject: \(info.signingAuthority[0])"
        )
        // Trust came from the requirement evaluation, not from that string.
        XCTAssertTrue(info.isAppleSigned)
    }

    // MARK: - Caching

    func testKnownTimestampMatchesDefaultLookup() {
        let verifier = SigningVerifier()
        let mtime = PathUtilities.timestamps(for: "/bin/ls").modified
        let withHint = verifier.verify(path: "/bin/ls", knownModDate: mtime)

        // A separate verifier, so the answer is recomputed rather than read from
        // the first instance's cache — the old test compared a value to itself.
        let fresh = SigningVerifier().verify(path: "/bin/ls")
        XCTAssertEqual(withHint, fresh)
    }

    func testResultsAreNotPersistedToDisk() throws {
        // Verification results are deliberately not written anywhere: a cache in a
        // location the audited user can write is a forgery primitive — malware
        // running as that user could pre-seed "Apple-signed, notarized" verdicts for
        // its own payload and the verifier would return them without ever calling
        // Security.framework.
        let caches = try XCTUnwrap(
            FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first
        )
        let legacy = caches.appendingPathComponent("LaunchAudit/SigningCache.plist")

        // Clear any file left by an older build so this asserts on *this* run.
        try? FileManager.default.removeItem(at: legacy)

        _ = SigningVerifier().verify(path: "/bin/ls")
        _ = SigningVerifier().verify(path: "/bin/sh")

        XCTAssertFalse(
            FileManager.default.fileExists(atPath: legacy.path),
            "SigningVerifier must not create a persistent, user-writable verdict cache"
        )
    }

    // MARK: - Entitlements

    func testEntitlementsAreExtractedWithoutFalsePositives() {
        // /bin/ls carries none of the dangerous entitlements.
        let info = SigningVerifier().verify(path: "/bin/ls")
        XCTAssertFalse(
            info.entitlements.contains("com.apple.security.cs.disable-library-validation")
        )
    }
}
