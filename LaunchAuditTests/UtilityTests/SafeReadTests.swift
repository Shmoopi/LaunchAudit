import XCTest
@testable import LaunchAudit

/// Tests for the guarded-read helper.
///
/// These cover the "hang the auditor" evasion: an attacker who can write a single
/// file in `$HOME` used to be able to stop every scan permanently by replacing a
/// shell profile with a FIFO, because `String(contentsOfFile:)` blocks forever
/// waiting for a writer.
final class SafeReadTests: XCTestCase {

    private var tempDir: URL!

    override func setUpWithError() throws {
        tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("SafeReadTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: tempDir, withIntermediateDirectories: true
        )
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: tempDir)
    }

    private func path(_ name: String) -> String {
        tempDir.appendingPathComponent(name).path
    }

    func testReadsRegularFile() throws {
        let file = path("config")
        try Data("export PATH=/usr/bin\n".utf8).write(to: URL(fileURLWithPath: file))

        let text = try SafeRead.text(atPath: file)
        XCTAssertEqual(text, "export PATH=/usr/bin\n")
    }

    func testReadsEmptyFile() throws {
        let file = path("empty")
        try Data().write(to: URL(fileURLWithPath: file))
        XCTAssertEqual(try SafeRead.text(atPath: file), "")
    }

    /// Ordinary symlinks are followed.
    ///
    /// Refusing every symlink was too blunt: macOS ships
    /// `/System/Library/LaunchAgents/*.plist` as symlinks into the Cryptex volume,
    /// so a blanket refusal silently dropped Safari's launch agents and a dozen
    /// other real items — the exact false-negative class this type exists to stop.
    func testFollowsOrdinarySymlink() throws {
        let target = path("real")
        try Data("contents\n".utf8).write(to: URL(fileURLWithPath: target))
        let link = path("link")
        try FileManager.default.createSymbolicLink(
            atPath: link, withDestinationPath: target
        )

        XCTAssertEqual(try SafeRead.text(atPath: link), "contents\n")
    }

    /// A symlink through to a non-regular file is still refused, so following one
    /// cannot reintroduce the FIFO hang.
    func testRefusesSymlinkToNonRegularFile() throws {
        let fifo = path("fifo")
        XCTAssertEqual(mkfifo(fifo, 0o644), 0)
        let link = path("link-to-fifo")
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: fifo)

        let finished = expectation(description: "returns")
        DispatchQueue.global().async {
            do {
                _ = try SafeRead.data(atPath: link)
                XCTFail("should not read a FIFO through a symlink")
            } catch let error as SafeRead.Failure {
                guard case .notRegularFile = error else {
                    return XCTFail("expected notRegularFile, got \(error)")
                }
            } catch {
                XCTFail("unexpected: \(error)")
            }
            finished.fulfill()
        }
        wait(for: [finished], timeout: 5)
    }

    func testRefusesFifoWithoutBlocking() throws {
        let fifo = path("blocking-profile")
        XCTAssertEqual(mkfifo(fifo, 0o644), 0, "could not create test FIFO")

        // The assertion that matters is that this call *returns at all*. Run it off
        // the test thread so a regression shows up as a timeout rather than as a
        // hung test process.
        let finished = expectation(description: "SafeRead returns on a FIFO")
        DispatchQueue.global().async {
            do {
                _ = try SafeRead.data(atPath: fifo)
                XCTFail("reading a FIFO should not succeed")
            } catch let error as SafeRead.Failure {
                guard case .notRegularFile = error else {
                    return XCTFail("expected notRegularFile, got \(error)")
                }
            } catch {
                XCTFail("unexpected error type: \(error)")
            }
            finished.fulfill()
        }
        wait(for: [finished], timeout: 5)
    }

    func testRefusesDirectory() throws {
        XCTAssertThrowsError(try SafeRead.data(atPath: tempDir.path)) { error in
            guard case SafeRead.Failure.notRegularFile = error else {
                return XCTFail("expected notRegularFile, got \(error)")
            }
        }
    }

    func testRefusesCharacterDevice() {
        // /dev/random never reaches EOF; an unbounded read would never return.
        XCTAssertThrowsError(try SafeRead.data(atPath: "/dev/random")) { error in
            guard case SafeRead.Failure.notRegularFile = error else {
                return XCTFail("expected notRegularFile, got \(error)")
            }
        }
    }

    func testEnforcesSizeCap() throws {
        let file = path("large")
        try Data(repeating: 0x41, count: 4096).write(to: URL(fileURLWithPath: file))

        XCTAssertThrowsError(try SafeRead.data(atPath: file, maxBytes: 1024)) { error in
            guard case SafeRead.Failure.tooLarge = error else {
                return XCTFail("expected tooLarge, got \(error)")
            }
        }
        // Within the cap it reads fine.
        XCTAssertEqual(try SafeRead.data(atPath: file, maxBytes: 8192).count, 4096)
    }

    func testMissingFileReportsCannotOpen() {
        XCTAssertThrowsError(try SafeRead.data(atPath: path("absent"))) { error in
            guard case SafeRead.Failure.cannotOpen = error else {
                return XCTFail("expected cannotOpen, got \(error)")
            }
        }
    }

    func testSizeReturnsNilForNonRegularFiles() throws {
        XCTAssertNil(SafeRead.size(atPath: tempDir.path))
        let file = path("sized")
        try Data(repeating: 0x42, count: 17).write(to: URL(fileURLWithPath: file))
        XCTAssertEqual(SafeRead.size(atPath: file), 17)
    }
}
