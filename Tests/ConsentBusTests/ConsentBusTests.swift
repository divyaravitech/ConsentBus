import XCTest
import CryptoKit
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
        // .expired only permits a forward transition to .pending (plus the
        // self-transition tested separately) — .revoked is genuinely invalid.
        XCTAssertThrowsError(try fsm.transition(to: .revoked)) { error in
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

    func testSameStateTransitionIsIdempotent() throws {
        var fsm = ConsentFSM()
        try fsm.transition(to: .revoked)
        // Re-asserting the current state must not throw — real callers need
        // this (e.g. re-broadcasting on launch, or syncing a late-joining
        // adapter to an already-established decision).
        try fsm.transition(to: .revoked)
        XCTAssertEqual(fsm.currentState, .revoked)
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

final class AuditLedgerPersistenceTests: XCTestCase {
    func testPersistedLedgerSurvivesReload() async throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("ConsentBusTests-\(UUID().uuidString)", isDirectory: true)
        let persistence = AuditLedgerPersistence(
            keychainService: "com.consentbus.tests.\(UUID().uuidString)",
            keychainAccount: "hmac-key",
            entriesFileURL: tempDir.appendingPathComponent("ledger.json")
        )
        let keyStore = KeychainKeyStore(service: persistence.keychainService, account: persistence.keychainAccount)
        defer {
            try? FileManager.default.removeItem(at: tempDir)
            keyStore.delete()
        }

        let receipt = AdapterReceipt(
            sdkIdentifier: "sdk.persist", sdkVersion: "1.0",
            appliedState: .revoked, purposeApplied: .analyticsStorage,
            nativeMethodCall: "test", success: true, status: .applied
        )

        let firstLedger = try AuditLedger(persistence: persistence)
        _ = try await firstLedger.commit(
            purpose: .analyticsStorage, appliedState: .revoked,
            sourceSignal: .userUI, receipts: [receipt]
        )
        let firstEntries = await firstLedger.allEntries()
        XCTAssertEqual(firstEntries.count, 1)

        // A second ledger instance pointed at the same persistence config
        // reloads the committed entry and its chain still verifies — this
        // is what makes the ledger real audit evidence instead of an
        // in-memory convenience log that vanishes on relaunch.
        let secondLedger = try AuditLedger(persistence: persistence)
        let reloadedEntries = await secondLedger.allEntries()
        XCTAssertEqual(reloadedEntries.count, 1)
        XCTAssertEqual(reloadedEntries.first?.currentHash, firstEntries.first?.currentHash)
        let isValid = await secondLedger.verifyChainIntegrity()
        XCTAssertTrue(isValid)
    }
}

final class ComplianceReportSigningTests: XCTestCase {
    func testReportSignatureVerifiesAgainstCorrectPublicKeyOnly() async throws {
        let ledger = AuditLedger()
        let signingKey = Curve25519.Signing.PrivateKey()
        let engine = ComplianceAttestationEngine(ledger: ledger, signingKey: signingKey)

        let receipt = AdapterReceipt(
            sdkIdentifier: "sdk.sign", sdkVersion: "1.0",
            appliedState: .revoked, purposeApplied: .analyticsStorage,
            nativeMethodCall: "test", success: true, status: .applied
        )
        _ = try await ledger.commit(
            purpose: .analyticsStorage, appliedState: .revoked,
            sourceSignal: .userUI, receipts: [receipt]
        )

        guard let report = await engine.generateReport() else {
            XCTFail("expected a report")
            return
        }

        XCTAssertTrue(ComplianceAttestationEngine.verify(report, publicKey: signingKey.publicKey))

        // A regulator handed only the report and the WRONG public key must
        // not be able to verify it — otherwise the signature proves nothing.
        let wrongKey = Curve25519.Signing.PrivateKey()
        XCTAssertFalse(ComplianceAttestationEngine.verify(report, publicKey: wrongKey.publicKey))
    }

    func testTamperedReportFailsSignatureVerification() async throws {
        let ledger = AuditLedger()
        let signingKey = Curve25519.Signing.PrivateKey()
        let engine = ComplianceAttestationEngine(ledger: ledger, signingKey: signingKey)

        // Two receipts with different outcomes so the real coverage score
        // (50%) is distinguishable from a tampered value — a single
        // APPLIED receipt would already compute to 100%, making a
        // "tamper to 100%" test vacuous.
        let appliedReceipt = AdapterReceipt(
            sdkIdentifier: "sdk.sign.a", sdkVersion: "1.0",
            appliedState: .revoked, purposeApplied: .analyticsStorage,
            nativeMethodCall: "test", success: true, status: .applied
        )
        let failedReceipt = AdapterReceipt(
            sdkIdentifier: "sdk.sign.b", sdkVersion: "1.0",
            appliedState: .revoked, purposeApplied: .analyticsStorage,
            nativeMethodCall: "test", success: false, status: .failed
        )
        _ = try await ledger.commit(
            purpose: .analyticsStorage, appliedState: .revoked,
            sourceSignal: .userUI, receipts: [appliedReceipt, failedReceipt]
        )

        guard let report = await engine.generateReport() else {
            XCTFail("expected a report")
            return
        }
        XCTAssertEqual(report.coverageScore, 50.0)

        let tampered = ComplianceAttestationReport(
            consentVersion: report.consentVersion,
            generatedAt: report.generatedAt,
            propagationTable: report.propagationTable,
            coverageScore: 100.0, // tampered: claim full coverage instead of 50%
            chainProof: report.chainProof,
            signature: report.signature
        )

        XCTAssertFalse(ComplianceAttestationEngine.verify(tampered, publicKey: signingKey.publicKey))
    }
}

final class AdapterReplayOnRegisterTests: XCTestCase {
    // ConsentBus.shared is a true singleton that persists to the REAL
    // Keychain/disk by default (that's the whole point of the persistence
    // fix) — any test that touches it, including this one, creates real
    // artifacts on the developer's machine. Clean them up so `swift test`
    // never leaves residue in the real login Keychain or on disk. Safe to
    // run even if ConsentBus.shared keeps working afterward for the rest
    // of this process: deleting the Keychain item doesn't affect an
    // already-initialized in-memory singleton, it only prevents leftover
    // persistence after the test process exits.
    override class func tearDown() {
        KeychainKeyStore(
            service: AuditLedgerPersistence.default.keychainService,
            account: AuditLedgerPersistence.default.keychainAccount
        ).delete()
        KeychainKeyStore(
            service: ConsentBus.signingKeyKeychainService,
            account: ConsentBus.signingKeyKeychainAccount
        ).delete()
        try? FileManager.default.removeItem(at: AuditLedgerPersistence.default.entriesFileURL)
        super.tearDown()
    }

    actor RecordingAdapter: ConsentAdapter {
        let sdkIdentifier = "test.late.adapter"
        let sdkVersion = "1.0.0"
        let capabilitySchema = ConsentCapabilitySchema(
            sdkIdentifier: "test.late.adapter",
            supportedPurposes: [.analyticsStorage]
        )
        private(set) var receivedEvents: [ConsentEvent] = []

        func apply(_ event: ConsentEvent) async -> AdapterReceipt {
            receivedEvents.append(event)
            return AdapterReceipt(
                sdkIdentifier: sdkIdentifier, sdkVersion: sdkVersion,
                appliedState: event.newState, purposeApplied: event.purpose,
                nativeMethodCall: "RecordingSDK.apply", success: true, status: .applied
            )
        }
    }

    func testLateRegisteringAdapterIsSyncedToExistingConsent() async throws {
        // ConsentBus.shared is a process-wide singleton, so scope this test
        // to a purpose no other test touches to avoid FSM-state collisions.
        let purpose = ConsentPurpose.guardianMediated
        _ = try await ConsentBus.shared.setConsent(.revoked, purpose: purpose, source: .userUI)

        let lateAdapter = RecordingAdapter()
        try await ConsentBus.shared.register(adapter: lateAdapter)

        let received = await lateAdapter.receivedEvents
        XCTAssertEqual(received.count, 1)
        XCTAssertEqual(received.first?.newState, .revoked)
        XCTAssertEqual(received.first?.purpose, purpose)
        XCTAssertEqual(received.first?.sourceSignal, .adapterSync)
    }
}
