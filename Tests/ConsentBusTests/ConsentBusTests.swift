import XCTest
import CryptoKit
@testable import ConsentBus

/// An isolated, in-memory ConsentBus: no Keychain, no disk, and no state
/// shared with any other test. Tests must not touch `ConsentBus.shared` —
/// it persists to the real Keychain/disk and is shared process-wide.
func makeIsolatedBus() -> ConsentBus {
    ConsentBus(
        ledger: AuditLedger(),
        signingKey: Curve25519.Signing.PrivateKey(),
        isPersistenceDegraded: false
    )
}

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

        let receipt = await makeIsolatedBus().dispatchWithRetry(adapter: adapter, event: event)

        XCTAssertTrue(receipt.success)
        XCTAssertEqual(receipt.status, .applied)
        XCTAssertEqual(receipt.attemptCount, 3, "should record it took 3 attempts to succeed")
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

        // A bare XCTest bundle for a Swift package (no host app, so no
        // real code-signing entitlements) cannot always reach the real
        // Keychain — confirmed empirically running this suite on iOS
        // Simulator. That's an environment limitation, not a regression:
        // skip honestly rather than fail, and rather than silently pass.
        // Relaunch behavior that does NOT need the real Keychain is covered
        // by RelaunchRestoreTests.
        let firstLedger: AuditLedger
        do {
            firstLedger = try AuditLedger(persistence: persistence)
        } catch {
            throw XCTSkip("Keychain unavailable in this test environment (\(error)) — cannot verify real persistence round-trip here.")
        }
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
            consentChangedAt: report.consentChangedAt,
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
        let bus = makeIsolatedBus()
        let purpose = ConsentPurpose.analyticsStorage
        _ = try await bus.setConsent(.revoked, purpose: purpose, source: .userUI)

        let lateAdapter = RecordingAdapter()
        try await bus.register(adapter: lateAdapter)

        let received = await lateAdapter.receivedEvents
        XCTAssertEqual(received.count, 1)
        XCTAssertEqual(received.first?.newState, .revoked)
        XCTAssertEqual(received.first?.purpose, purpose)
        XCTAssertEqual(received.first?.sourceSignal, .adapterSync)
    }

    func testDuplicateAdapterRegistrationThrows() async throws {
        actor DuplicateIdentifierAdapter: ConsentAdapter {
            let sdkIdentifier = "test.duplicate.adapter"
            let sdkVersion = "1.0.0"
            let capabilitySchema = ConsentCapabilitySchema(
                sdkIdentifier: "test.duplicate.adapter",
                supportedPurposes: [.measurement]
            )
            func apply(_ event: ConsentEvent) async -> AdapterReceipt {
                AdapterReceipt(
                    sdkIdentifier: sdkIdentifier, sdkVersion: sdkVersion,
                    appliedState: event.newState, purposeApplied: event.purpose,
                    nativeMethodCall: "N/A", success: true, status: .applied
                )
            }
        }

        let bus = makeIsolatedBus()
        try await bus.register(adapter: DuplicateIdentifierAdapter())

        do {
            try await bus.register(adapter: DuplicateIdentifierAdapter())
            XCTFail("expected registering a second adapter with the same sdkIdentifier to throw")
        } catch ConsentBusError.duplicateAdapter(let sdkIdentifier) {
            XCTAssertEqual(sdkIdentifier, "test.duplicate.adapter")
        }
    }

    /// A sequential duplicate check alone doesn't prove the guard is
    /// race-free — the actual bug this guards against only shows up under
    /// real concurrent registration, since `await adapter.sdkIdentifier`
    /// inside the old check was a genuine suspension point two reentrant
    /// register() calls could interleave across. Fire many concurrent
    /// registrations of adapters that all share one sdkIdentifier and
    /// verify exactly one succeeds.
    func testConcurrentDuplicateRegistrationOnlyOneSucceeds() async throws {
        actor ConcurrentDuplicateAdapter: ConsentAdapter {
            let sdkIdentifier = "test.concurrent.duplicate.adapter"
            let sdkVersion = "1.0.0"
            let capabilitySchema = ConsentCapabilitySchema(
                sdkIdentifier: "test.concurrent.duplicate.adapter",
                supportedPurposes: [.functional]
            )
            func apply(_ event: ConsentEvent) async -> AdapterReceipt {
                AdapterReceipt(
                    sdkIdentifier: sdkIdentifier, sdkVersion: sdkVersion,
                    appliedState: event.newState, purposeApplied: event.purpose,
                    nativeMethodCall: "N/A", success: true, status: .applied
                )
            }
        }

        let bus = makeIsolatedBus()
        let successCount = await withTaskGroup(of: Bool.self) { group in
            for _ in 0..<20 {
                group.addTask {
                    (try? await bus.register(adapter: ConcurrentDuplicateAdapter())) != nil
                }
            }
            var successes = 0
            for await succeeded in group where succeeded {
                successes += 1
            }
            return successes
        }

        XCTAssertEqual(successCount, 1, "exactly one of 20 concurrent registrations sharing an sdkIdentifier should succeed")
    }
}

final class AdapterTimeoutTests: XCTestCase {
    actor HangingAdapter: ConsentAdapter {
        let sdkIdentifier = "test.hanging.adapter"
        let sdkVersion = "1.0.0"
        let capabilitySchema = ConsentCapabilitySchema(
            sdkIdentifier: "test.hanging.adapter",
            supportedPurposes: [.analyticsStorage]
        )

        // Blocks the underlying thread with Thread.sleep rather than
        // Task.sleep deliberately: Task.sleep is cancellation-aware and
        // would pass this test even against a *broken* timeout
        // implementation, giving false confidence — exactly the trap an
        // earlier version of this test fell into. A real vendor SDK's
        // blocking network call won't check Task.isCancelled either, so
        // this is the more faithful (if uglier) simulation. Sleeps far
        // longer than ConsentBus's own adapter timeout, so it's genuinely
        // that timeout producing a result here, not this sleep ending.
        // Thread.sleep is marked noasync (a warning today, a hard error
        // under Swift 6 language mode) if called directly from an async
        // function — routing it through this plain synchronous function
        // avoids that while keeping the actual blocking behavior identical.
        nonisolated func blockThreadSynchronously(seconds: TimeInterval) {
            Thread.sleep(forTimeInterval: seconds)
        }

        func apply(_ event: ConsentEvent) async -> AdapterReceipt {
            blockThreadSynchronously(seconds: 3600) // 1 hour, non-cancellable
            return AdapterReceipt(
                sdkIdentifier: sdkIdentifier, sdkVersion: sdkVersion,
                appliedState: event.newState, purposeApplied: event.purpose,
                nativeMethodCall: "should never be reached", success: true, status: .applied
            )
        }
    }

    // Deliberately slow (~10s, ConsentBus's fixed adapter timeout) — tests
    // applyWithTimeout directly rather than through dispatchWithRetry's
    // full retry wrapper (which would multiply this by up to 4x). Worth
    // the cost: this is exactly the property whose absence caused a real
    // crash bug earlier (a hung/failing adapter taking down the process
    // instead of timing out), so it should be verified for real, not just
    // reviewed by eye.
    func testHungAdapterTimesOutInsteadOfBlockingForever() async throws {
        let adapter = HangingAdapter()
        let event = ConsentEvent(
            previousState: .unknown, newState: .revoked,
            purpose: .analyticsStorage, version: 1, sourceSignal: .userUI
        )

        let start = Date()
        let receipt = await makeIsolatedBus().applyWithTimeout(adapter: adapter, event: event)
        let elapsed = Date().timeIntervalSince(start)

        XCTAssertLessThan(elapsed, 30, "a hung adapter must never block dispatch indefinitely")
        XCTAssertEqual(receipt.status, .failed)
        XCTAssertTrue(receipt.errorDescription?.contains("timed out") == true)
    }
}

final class RelaunchRestoreTests: XCTestCase {
    private func emptyCommit(_ ledger: AuditLedger, _ purpose: ConsentPurpose, _ state: ConsentState) async throws -> LedgerEntry {
        try await ledger.commit(purpose: purpose, appliedState: state, sourceSignal: .userUI, receipts: [])
    }

    func testRestoredConsentStatesKeepTheLatestStatePerPurposeAndContinueTheChain() async throws {
        let key = SymmetricKey(size: .bits256)
        let original = AuditLedger(hmacKey: key)
        _ = try await emptyCommit(original, .analyticsStorage, .granted)
        _ = try await emptyCommit(original, .adStorage, .revoked)
        _ = try await emptyCommit(original, .analyticsStorage, .revoked)
        let persisted = await original.allEntries()

        let relaunched = AuditLedger(hmacKey: key, restoringEntries: persisted)

        let restoredStates = await relaunched.restoredConsentStates
        XCTAssertEqual(restoredStates, [.analyticsStorage: .revoked, .adStorage: .revoked])
        let intact = await relaunched.verifyChainIntegrity()
        XCTAssertTrue(intact)
        let next = try await emptyCommit(relaunched, .measurement, .granted)
        XCTAssertEqual(next.version, 4)
        XCTAssertEqual(next.previousHash, persisted.last?.currentHash)
    }

    /// The scenario that mattered: a revocation made in one session must still
    /// be in force after a relaunch, and adapters registered at that launch
    /// must be re-synced to it. Before state restoration, a relaunch reset
    /// every purpose to `.unknown`, so nothing was replayed and an SDK that
    /// resets to its own (typically opt-in) default each launch resumed
    /// collecting data the user had already revoked.
    func testRelaunchKeepsRevocationInForceAndResyncsAdaptersRegisteredAtLaunch() async throws {
        let key = SymmetricKey(size: .bits256)
        let signingKey = Curve25519.Signing.PrivateKey()

        let firstLaunchLedger = AuditLedger(hmacKey: key)
        let firstLaunch = ConsentBus(ledger: firstLaunchLedger, signingKey: signingKey, isPersistenceDegraded: false)
        _ = try await firstLaunch.setConsent(.revoked, purpose: .analyticsStorage, source: .userUI)
        let persisted = await firstLaunchLedger.allEntries()

        let secondLaunch = ConsentBus(
            ledger: AuditLedger(hmacKey: key, restoringEntries: persisted),
            signingKey: signingKey,
            isPersistenceDegraded: false
        )
        let restored = await secondLaunch.currentConsentState(for: .analyticsStorage)
        XCTAssertEqual(restored, .revoked)

        let sdk = AdapterReplayOnRegisterTests.RecordingAdapter()
        try await secondLaunch.register(adapter: sdk)
        let events = await sdk.receivedEvents
        XCTAssertEqual(events.count, 1)
        XCTAssertEqual(events.first?.newState, .revoked)
        XCTAssertEqual(events.first?.sourceSignal, .adapterSync)

        let chainIntact = await secondLaunch.verifyAuditChainIntegrity()
        XCTAssertTrue(chainIntact)

        // The restored state is a real state, not a blank slate: it still
        // enforces the transition rules.
        do {
            _ = try await secondLaunch.setConsent(.expired, purpose: .analyticsStorage, source: .userUI)
            XCTFail("revoked -> expired is not a valid transition and must still be rejected after a relaunch")
        } catch is ConsentError {}
    }
}

final class ConsentOperationSerializationTests: XCTestCase {
    /// Records the wall-clock interval each `apply` call occupies, sleeping
    /// in the middle so overlapping operations would be unmistakable.
    actor IntervalRecordingAdapter: ConsentAdapter {
        let sdkIdentifier = "test.interval.adapter"
        let sdkVersion = "1.0.0"
        let capabilitySchema = ConsentCapabilitySchema(
            sdkIdentifier: "test.interval.adapter",
            supportedPurposes: Set(ConsentPurpose.allCases)
        )
        private(set) var intervals: [(start: ContinuousClock.Instant, end: ContinuousClock.Instant)] = []

        func apply(_ event: ConsentEvent) async -> AdapterReceipt {
            let start = ContinuousClock.now
            try? await Task.sleep(nanoseconds: 150_000_000)
            intervals.append((start, ContinuousClock.now))
            return AdapterReceipt(
                sdkIdentifier: sdkIdentifier, sdkVersion: sdkVersion,
                appliedState: event.newState, purposeApplied: event.purpose,
                nativeMethodCall: "IntervalSDK.apply", success: true, status: .applied
            )
        }
    }

    /// Swift actors are reentrant across `await`, so being an actor does not
    /// by itself stop two `setConsent` calls from interleaving their dispatch
    /// phases. ConsentBus's documented ordering guarantee — one operation's
    /// dispatch never overlaps another's — has to be enforced explicitly.
    func testConcurrentConsentOperationsNeverOverlapTheirDispatch() async throws {
        let bus = makeIsolatedBus()
        let adapter = IntervalRecordingAdapter()
        try await bus.register(adapter: adapter)

        let purposes: [ConsentPurpose] = [.analyticsStorage, .adStorage, .adPersonalization, .measurement]
        try await withThrowingTaskGroup(of: Void.self) { group in
            for purpose in purposes {
                group.addTask { _ = try await bus.setConsent(.revoked, purpose: purpose, source: .userUI) }
            }
            try await group.waitForAll()
        }

        let intervals = await adapter.intervals.sorted { $0.start < $1.start }
        XCTAssertEqual(intervals.count, purposes.count)
        for (earlier, later) in zip(intervals, intervals.dropFirst()) {
            XCTAssertLessThanOrEqual(earlier.end, later.start, "two consent operations were dispatching at the same time")
        }
    }
}
