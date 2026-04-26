import XCTest
@testable import LaunchAudit

final class KextScannerTests: XCTestCase {

    func testScannerCategory() {
        let scanner = KextScanner()
        XCTAssertEqual(scanner.category, .kernelExtensions)
    }

    func testScanCompletesPromptly() async throws {
        let scanner = KextScanner()
        let start = Date()
        _ = try await scanner.scan()
        let elapsed = Date().timeIntervalSince(start)
        XCTAssertLessThan(elapsed, 5.0)
    }

    func testParseKmutilOutputAcceptsValidBundleIDs() {
        // Realistic kmutil output snippet — bundle IDs follow reverse-DNS form.
        let output = """
        Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
            1   85 0xfffffe0008e30000 0x1ed0     0x1ed0     com.apple.kpi.bsd (26.2)
            2   42 0xfffffe0008e32000 0x500      0x500      com.apple.driver.usb.AppleUSBHostMergeProperties (1.2)
        """
        let scanner = KextScanner()
        let ids = scanner.parseLoadedBundleIDsForTesting(output)
        XCTAssertTrue(ids.contains("com.apple.kpi.bsd"),
            "Should extract com.apple.kpi.bsd")
        XCTAssertTrue(ids.contains("com.apple.driver.usb.AppleUSBHostMergeProperties"))
    }

    func testParseKmutilOutputRejectsNumbersAndPaths() {
        // Numbers, paths, and parenthesized hex shouldn't be misclassified as
        // bundle IDs even though they may contain dots.
        let output = """
            1   85 0xfffffe0008e30000 192.168.1.1 com.example.fake (1.0) (foo.bar)
        """
        let scanner = KextScanner()
        let ids = scanner.parseLoadedBundleIDsForTesting(output)
        XCTAssertFalse(ids.contains("192.168.1.1"),
            "IP address should not be classified as a bundle ID")
        XCTAssertFalse(ids.contains("(foo.bar)"),
            "Parenthesized values should be rejected")
        XCTAssertTrue(ids.contains("com.example.fake"),
            "Valid bundle ID should still be extracted")
    }
}
