import XCTest
@testable import ConsentBus

final class ConsentFSMTests: XCTestCase {
    func testValidTransition() throws {
        var fsm = ConsentFSM()
        XCTAssertEqual(fsm.currentState, .unknown)
        try fsm.transition(to: .granted)
        XCTAssertEqual(fsm.currentState, .granted)
    }

    func testInvalidTransitionThrows() throws {
        var fsm = ConsentFSM()
        try fsm.transition(to: .granted)
        try fsm.transition(to: .expired)
        XCTAssertThrowsError(try fsm.transition(to: .expired)) { error in
            XCTAssertTrue(error is ConsentError)
        }
    }
}

final class ComplianceCoverageScoreTests: XCTestCase {
    func testFullCoverage() {
        let receipts = [
            AdapterReceipt(sdkIdentifier: "a", sdkVersion: "1.0", appliedState: .revoked,
                            purposeApplied: .analyticsStorage, nativeMethodCall: "x",
                            success: true, status: .applied)
        ]
        XCTAssertEqual(ComplianceAttestationEngine.computeCoverageScore(receipts: receipts), 100.0)
    }

    func testPartialCoverageExcludesNotSupported() {
        let receipts = [
            AdapterReceipt(sdkIdentifier: "a", sdkVersion: "1.0", appliedState: .revoked,
                            purposeApplied: .analyticsStorage, nativeMethodCall: "x",
                            success: true, status: .applied),
            AdapterReceipt(sdkIdentifier: "b", sdkVersion: "1.0", appliedState: .revoked,
                            purposeApplied: .analyticsStorage, nativeMethodCall: "y",
                            success: false, status: .failed),
            AdapterReceipt(sdkIdentifier: "c", sdkVersion: "1.0", appliedState: .revoked,
                            purposeApplied: .locationPrecise, nativeMethodCall: "z",
                            success: false, status: .notSupported)
        ]
        // 1 applied / (1 applied + 1 failed) = 50%, c excluded entirely
        XCTAssertEqual(ComplianceAttestationEngine.computeCoverageScore(receipts: receipts), 50.0)
    }
}

final class AuditLedgerTests: XCTestCase {
    func testChainIntegrityHoldsAfterMultipleCommits() async throws {
        let ledger = AuditLedger()
        for i in 0..<5 {
            let receipt = AdapterReceipt(
                sdkIdentifier: "sdk.\(i)", sdkVersion: "1.0",
                appliedState: .granted, purposeApplied: .analyticsStorage,
                nativeMethodCall: "test", success: true, status: .applied
            )
            _ = try await ledger.commit(
                purpose: .analyticsStorage, appliedState: .granted,
                sourceSignal: .userUI, receipts: [receipt]
            )
        }
        let isValid = await ledger.verifyChainIntegrity()
        XCTAssertTrue(isValid)
    }
}
