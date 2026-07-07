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

    func testExpiredToGrantedThrows() throws {
        var fsm = ConsentFSM()
        try fsm.transition(to: .granted)
        try fsm.transition(to: .expired)
        XCTAssertThrowsError(try fsm.transition(to: .granted)) { error in
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

    func testAllNotSupportedReturns100() {
        let receipts = [
            AdapterReceipt(sdkIdentifier: "a", sdkVersion: "1.0", appliedState: .revoked,
                            purposeApplied: .locationPrecise, nativeMethodCall: "N/A",
                            success: false, status: .notSupported),
            AdapterReceipt(sdkIdentifier: "b", sdkVersion: "1.0", appliedState: .revoked,
                            purposeApplied: .guardianMediated, nativeMethodCall: "N/A",
                            success: false, status: .notSupported)
        ]
        XCTAssertEqual(ComplianceAttestationEngine.computeCoverageScore(receipts: receipts), 100.0)
    }

    func testAllFailedReturns0() {
        let receipts = [
            AdapterReceipt(sdkIdentifier: "a", sdkVersion: "1.0", appliedState: .revoked,
                            purposeApplied: .analyticsStorage, nativeMethodCall: "x",
                            success: false, status: .failed),
            AdapterReceipt(sdkIdentifier: "b", sdkVersion: "1.0", appliedState: .revoked,
                            purposeApplied: .analyticsStorage, nativeMethodCall: "y",
                            success: false, status: .failed)
        ]
        XCTAssertEqual(ComplianceAttestationEngine.computeCoverageScore(receipts: receipts), 0.0)
    }

    func testEmptyReceiptsReturns100() {
        XCTAssertEqual(ComplianceAttestationEngine.computeCoverageScore(receipts: []), 100.0)
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

    func testTamperedReceiptFailsChainIntegrity() async throws {
        let ledger = AuditLedger()
        for i in 0..<3 {
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

        let validBeforeTamper = await ledger.verifyChainIntegrity()
        XCTAssertTrue(validBeforeTamper)

        // Corrupt the sdkVersion field of the receipt in the middle entry,
        // simulating tampering with the committed ledger without going
        // through commit() (which would recompute the hash correctly).
        let entries = await ledger.allEntries()
        let originalReceipt = entries[1].receipts[0]
        let tamperedReceipt = AdapterReceipt(
            sdkIdentifier: originalReceipt.sdkIdentifier,
            sdkVersion: "9.9.9-TAMPERED",
            appliedState: originalReceipt.appliedState,
            purposeApplied: originalReceipt.purposeApplied,
            nativeMethodCall: originalReceipt.nativeMethodCall,
            success: originalReceipt.success,
            status: originalReceipt.status
        )
        await ledger._testOnly_corruptEntry(at: 1, receipts: [tamperedReceipt])

        let validAfterTamper = await ledger.verifyChainIntegrity()
        XCTAssertFalse(validAfterTamper)
    }
}

final class RetryMechanismTests: XCTestCase {
    actor FailTwiceThenSucceedAdapter: ConsentAdapter {
        let sdkIdentifier = "test.retry.adapter"
        let sdkVersion = "1.0.0"
        let capabilitySchema = ConsentCapabilitySchema(
            sdkIdentifier: "test.retry.adapter",
            supportedPurposes: [.analyticsStorage]
        )
        private(set) var callCount = 0

        func apply(_ event: ConsentEvent) async -> AdapterReceipt {
            callCount += 1
            guard callCount >= 3 else {
                return AdapterReceipt(
                    sdkIdentifier: sdkIdentifier, sdkVersion: sdkVersion,
                    appliedState: event.newState, purposeApplied: event.purpose,
                    nativeMethodCall: "N/A", success: false, status: .failed,
                    errorDescription: "simulated failure #\(callCount)"
                )
            }
            return AdapterReceipt(
                sdkIdentifier: sdkIdentifier, sdkVersion: sdkVersion,
                appliedState: event.newState, purposeApplied: event.purpose,
                nativeMethodCall: "TestSDK.apply(\(event.purpose.rawValue))",
                success: true, status: .applied
            )
        }
    }

    func testRetrySucceedsOnThirdAttempt() async throws {
        let adapter = FailTwiceThenSucceedAdapter()
        let event = ConsentEvent(
            previousState: .unknown, newState: .revoked,
            purpose: .analyticsStorage, version: 1, sourceSignal: .userUI
        )

        let receipt = await ConsentBus.shared.dispatchWithRetry(adapter: adapter, event: event)

        XCTAssertTrue(receipt.success)
        XCTAssertEqual(receipt.status, .applied)
        let finalCallCount = await adapter.callCount
        XCTAssertEqual(finalCallCount, 3)
    }
}

final class NotSupportedDistinctionTests: XCTestCase {
    func testUnsupportedPurposeReturnsNotSupportedNotFailed() async {
        let adapter = FirebaseConsentAdapterExample()
        let event = ConsentEvent(
            previousState: .unknown, newState: .revoked,
            purpose: .locationPrecise, version: 1, sourceSignal: .userUI
        )

        let receipt = await adapter.apply(event)

        XCTAssertEqual(receipt.status, .notSupported)
        XCTAssertNotEqual(receipt.status, .failed)
        XCTAssertFalse(receipt.success)
    }
}
