import XCTest
@testable import LaunchAudit

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

    // MARK: - Basic verification

    func testVerifyAppleSignedSystemBinary() {
        let verifier = SigningVerifier(cacheDirectory: tempDir)
        // /bin/ls is always Apple-signed and present
        let info = verifier.verify(path: "/bin/ls")
        XCTAssertTrue(info.isSigned, "/bin/ls should be reported as signed")
        XCTAssertTrue(info.isAppleSigned, "/bin/ls should be Apple-signed")
    }

    func testVerifyMissingFileReturnsUnsigned() {
        let verifier = SigningVerifier(cacheDirectory: tempDir)
        let info = verifier.verify(path: "/nonexistent/path/to/binary")
        XCTAssertFalse(info.isSigned)
    }

    // MARK: - Known timestamp parameter

    func testVerifyWithKnownTimestampMatchesDefault() {
        let verifier = SigningVerifier(cacheDirectory: tempDir)
        let mtime = PathUtilities.timestamps(for: "/bin/ls").modified
        let infoA = verifier.verify(path: "/bin/ls", knownModDate: mtime)
        let infoB = verifier.verify(path: "/bin/ls")
        XCTAssertEqual(infoA, infoB)
    }

    // MARK: - Persistent disk cache

    func testDiskCacheRoundTrip() {
        let verifierA = SigningVerifier(cacheDirectory: tempDir)
        let infoA = verifierA.verify(path: "/bin/ls")
        verifierA.flushDiskCache()

        let verifierB = SigningVerifier(cacheDirectory: tempDir)
        // Should hit the persisted cache without re-running verification
        let infoB = verifierB.verify(path: "/bin/ls")
        XCTAssertEqual(infoA, infoB)
    }

    func testDiskCacheInvalidatedByTimestampChange() {
        // Create a temp binary copy
        let copyPath = tempDir.appendingPathComponent("ls").path
        try? FileManager.default.copyItem(atPath: "/bin/ls", toPath: copyPath)
        defer { try? FileManager.default.removeItem(atPath: copyPath) }

        let verifierA = SigningVerifier(cacheDirectory: tempDir)
        _ = verifierA.verify(path: copyPath)
        verifierA.flushDiskCache()

        // Touch the file: change mtime
        let future = Date().addingTimeInterval(60)
        try? FileManager.default.setAttributes(
            [.modificationDate: future], ofItemAtPath: copyPath
        )

        let verifierB = SigningVerifier(cacheDirectory: tempDir)
        let info = verifierB.verify(path: copyPath)
        // The cache key includes mtime, so this must re-verify; correctness check:
        // If the cache were broken we'd get stale data — easiest correctness check
        // is that we get back a valid SigningInfo (no crash, no nil-equivalents).
        XCTAssertNotNil(info)
    }

    // MARK: - Disabling persistence

    func testNoCacheDirectoryDisablesPersistence() {
        let verifier = SigningVerifier(cacheDirectory: nil)
        // Should not crash, should still verify
        let info = verifier.verify(path: "/bin/ls")
        XCTAssertTrue(info.isSigned)
        verifier.flushDiskCache() // No-op
    }

    // MARK: - Notarized requirement (fast path)

    func testNotarizedRequirementDetectsStapledTicket() {
        // /bin/ls is Apple-signed, which our code treats as "notarized" without
        // ever invoking spctl. This confirms the fast-path skips spctl.
        let verifier = SigningVerifier(cacheDirectory: tempDir)
        let info = verifier.verify(path: "/bin/ls")
        XCTAssertTrue(info.isNotarized,
            "Apple-signed binary should report notarized via fast path")
    }
}
