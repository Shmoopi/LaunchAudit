import XCTest
@testable import LaunchAudit

@MainActor
final class PrivilegeBannerVisibilityTests: XCTestCase {

    func testBannerHiddenWhenStatusUnknown() {
        let vm = ScanViewModel()
        vm.privilegeStatus = .unknown
        XCTAssertFalse(vm.shouldShowPrivilegeBanner,
            "Pre-scan (status .unknown) should not show the banner")
    }

    func testBannerHiddenWhenEnabled() {
        let vm = ScanViewModel()
        vm.privilegeStatus = .enabled
        XCTAssertFalse(vm.shouldShowPrivilegeBanner,
            "Helper enabled — no need to nag the user")
    }

    func testBannerShownWhenRequiresApproval() {
        let vm = ScanViewModel()
        vm.privilegeStatus = .requiresApproval
        XCTAssertTrue(vm.shouldShowPrivilegeBanner,
            ".requiresApproval is the canonical reason to surface the banner")
    }

    func testBannerShownWhenInstallFailed() {
        let vm = ScanViewModel()
        vm.privilegeStatus = .failed("XPC connection failed")
        XCTAssertTrue(vm.shouldShowPrivilegeBanner,
            "Failure is also actionable — show the banner so the user can retry")
    }

    func testDismissHidesBannerEvenWhenRequiresApproval() {
        let vm = ScanViewModel()
        vm.privilegeStatus = .requiresApproval
        vm.dismissPrivilegeBanner()
        XCTAssertFalse(vm.shouldShowPrivilegeBanner,
            "Once dismissed in this session, banner stays hidden")
    }

    func testNewScanResetsDismissalIfStatusChanges() async {
        let vm = ScanViewModel()
        vm.privilegeStatus = .requiresApproval
        vm.dismissPrivilegeBanner()
        XCTAssertFalse(vm.shouldShowPrivilegeBanner)

        // Simulate a fresh scan attempt — dismissal should reset so the
        // banner can re-appear if the status is still problematic.
        vm.resetPrivilegeBannerDismissal()
        XCTAssertTrue(vm.shouldShowPrivilegeBanner,
            "Dismissal should reset on each new scan so the user is re-prompted")
    }

    // MARK: - Failure message exposure

    func testFailureMessageReachableForUI() {
        let vm = ScanViewModel()
        vm.privilegeStatus = .failed("XPC connection failed")
        XCTAssertEqual(vm.privilegeFailureMessage, "XPC connection failed",
            "UI must surface the failure message so users know what happened")
    }

    func testNoFailureMessageWhenNotFailed() {
        let vm = ScanViewModel()
        vm.privilegeStatus = .requiresApproval
        XCTAssertNil(vm.privilegeFailureMessage)
    }
}
