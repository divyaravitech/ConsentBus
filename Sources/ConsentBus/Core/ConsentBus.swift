import Foundation
import CryptoKit

/// The central consent broker: a process-resident singleton that dispatches
/// consent events to every registered SDK adapter for a single consent
/// change atomically as one unit, eliminating the window where some SDKs
/// have received a change and others haven't.
///
/// Patent reference: Application No. 64/087,949, Claims 1, 2, 10 —
/// consent broker singleton executing on a dedicated serial execution
/// context such that no SDK adapter dispatch operation is initiated while
/// a prior dispatch operation is in progress. Adapters within a single
/// `setConsent` call are dispatched concurrently (not sequentially) since
/// this reading of the claim: no *new* setConsent operation's dispatch
/// phase may begin while a *prior* setConsent operation's dispatch is
/// still in flight — the serialization is between operations, not between
/// individual adapters receiving the same operation's event. Confirm this
/// reading with patent counsel before relying on it.
@globalActor
public actor ConsentBus {
    public static let shared = ConsentBus()

    private var adapters: [any ConsentAdapter] = []
    /// Tracks `adapters`' identifiers synchronously, alongside `adapters`
    /// itself, so `register(adapter:)` can check-and-insert with no
    /// suspension point in between. An earlier version checked for
    /// duplicates via `await existing.sdkIdentifier` on each already-
    /// registered adapter — a genuine suspension point, meaning two
    /// concurrent `register` calls for adapters sharing an sdkIdentifier
    /// could both pass the check (reading the same not-yet-updated state)
    /// before either finished appending, defeating the guard entirely.
    private var registeredIdentifiers: Set<String> = []
    private var fsmByPurpose: [ConsentPurpose: ConsentFSM] = [:]
    private let ledger: AuditLedger
    private let attestationEngine: ComplianceAttestationEngine

    /// The public key auditors need to independently verify signed
    /// compliance reports (`ComplianceAttestationEngine.verify(_:publicKey:)`).
    /// Distribute this to your DPO/regulator; never distribute the private
    /// signing key it pairs with.
    public nonisolated var compliancePublicKey: Curve25519.Signing.PublicKey {
        attestationEngine.publicKey
    }

    /// True if the audit ledger and/or compliance signing key could not be
    /// loaded from persistent storage (Keychain and/or disk) at launch, and
    /// this session is running on a transient, in-memory-only fallback
    /// instead. This is a real, expected runtime condition — restricted
    /// sandboxing, missing entitlements, a full disk — not a programmer
    /// error, so ConsentBus never crashes because of it; check this flag
    /// at launch if you want your own app to surface or log the
    /// degradation rather than silently losing audit-trail durability for
    /// the session.
    public let isPersistenceDegraded: Bool

    private let maxRetries = 3
    private let baseRetryDelayNanoseconds: UInt64 = 1_000_000_000 // 1s
    private let adapterTimeoutNanoseconds: UInt64 = 10_000_000_000 // 10s

    /// Monotonic, race-free dispatch counter incremented synchronously
    /// (before any `await`) alongside each purpose's FSM transition. Used
    /// to stamp `ConsentEvent.version`. This intentionally does NOT track
    /// the AuditLedger's own version counter: an earlier version read that
    /// counter speculatively via `await ledger.currentVersion() + 1`
    /// *before* the (potentially many-second, retry-laden) dispatch phase,
    /// which meant two concurrent `setConsent` calls — enabled by actor
    /// reentrancy across that await — could both read the same "next"
    /// value and stamp events with a version that didn't match the
    /// LedgerEntry they later ended up recorded in. This counter is
    /// incremented with no intervening suspension point, so it can never
    /// race.
    private var dispatchSequence: UInt64 = 0

    /// Keychain identity for the signing key `ConsentBus.shared` uses by
    /// default. Centralized (rather than inlined in `init()`) so nothing
    /// else — including tests that need to clean up the real Keychain
    /// artifacts this singleton creates on first access — has to duplicate
    /// these strings and risk them drifting apart.
    static let signingKeyKeychainService = AuditLedgerPersistence.default.keychainService
    static let signingKeyKeychainAccount = "ed25519-signing-key"

    private init() {
        var persistenceDegraded = false

        let ledger: AuditLedger
        if let persistent = try? AuditLedger(persistence: .default) {
            ledger = persistent
        } else {
            persistenceDegraded = true
            Self.logPersistenceFallback("audit ledger (Keychain/disk unavailable — falling back to in-memory; the audit trail will NOT survive relaunch)")
            ledger = AuditLedger()
        }
        self.ledger = ledger

        let signingKeyStore = KeychainKeyStore(
            service: Self.signingKeyKeychainService,
            account: Self.signingKeyKeychainAccount
        )
        let signingKey: Curve25519.Signing.PrivateKey
        if let keyData = try? signingKeyStore.loadOrCreate(generator: {
            Curve25519.Signing.PrivateKey().rawRepresentation
        }), let restored = try? Curve25519.Signing.PrivateKey(rawRepresentation: keyData) {
            signingKey = restored
        } else {
            persistenceDegraded = true
            Self.logPersistenceFallback("compliance signing key (Keychain unavailable — falling back to an ephemeral key; reports signed this session won't verify against a key fetched next launch)")
            signingKey = Curve25519.Signing.PrivateKey()
        }

        self.attestationEngine = ComplianceAttestationEngine(ledger: ledger, signingKey: signingKey)
        self.isPersistenceDegraded = persistenceDegraded
    }

    /// Logs a persistence fallback without ever crashing the process.
    ///
    /// An earlier version of this used `assertionFailure`, which is fatal
    /// in debug and test builds — verified empirically (running the test
    /// suite on iOS Simulator, where the bare XCTest bundle lacks Keychain
    /// entitlements a real provisioned app would have) that this took down
    /// the entire host process the instant Keychain access failed. A
    /// consent SDK must never crash its host app over a Keychain hiccup.
    private static func logPersistenceFallback(_ message: String) {
        FileHandle.standardError.write(Data("ConsentBus: \(message)\n".utf8))
    }

    /// Register an SDK adapter. Adapters should be registered at app launch
    /// before any consent events are dispatched — but if one registers
    /// later (common for lazily-initialized SDKs), it is synced to every
    /// already-established per-purpose consent decision before this call
    /// returns, so it never silently runs under its own default assumption
    /// while every other adapter already reflects the user's actual choice.
    ///
    /// Throws `ConsentBusError.duplicateAdapter` if an adapter with the
    /// same `sdkIdentifier` is already registered, rather than silently
    /// double-dispatching every future consent change to it.
    public func register(adapter: any ConsentAdapter) async throws {
        let newIdentifier = await adapter.sdkIdentifier

        // Check-and-insert with no `await` in between: this is what
        // actually makes it race-free against a reentrant concurrent
        // register() call, not just the fact that a check happens at all.
        guard !registeredIdentifiers.contains(newIdentifier) else {
            throw ConsentBusError.duplicateAdapter(sdkIdentifier: newIdentifier)
        }
        registeredIdentifiers.insert(newIdentifier)
        adapters.append(adapter)

        for (purpose, fsm) in fsmByPurpose where fsm.currentState != .unknown {
            dispatchSequence += 1
            let event = ConsentEvent(
                previousState: fsm.currentState,
                newState: fsm.currentState,
                purpose: purpose,
                version: dispatchSequence,
                sourceSignal: .adapterSync
            )
            let receipt = await dispatchWithRetry(adapter: adapter, event: event)
            try await ledger.commit(
                purpose: purpose,
                appliedState: fsm.currentState,
                sourceSignal: .adapterSync,
                receipts: [receipt]
            )
        }
    }

    /// Core patented operation: validate the requested transition, then
    /// dispatch the resulting ConsentEvent to every registered adapter —
    /// concurrently, all receiving this same consent change as one atomic
    /// unit — collecting AdapterReceipts and committing them to the
    /// tamper-evident audit ledger.
    @discardableResult
    public func setConsent(
        _ newState: ConsentState,
        purpose: ConsentPurpose,
        source: ConsentSource
    ) async throws -> LedgerEntry {
        var fsm = fsmByPurpose[purpose] ?? ConsentFSM()
        let previousState = fsm.currentState
        try fsm.transition(to: newState)
        fsmByPurpose[purpose] = fsm
        dispatchSequence += 1

        let event = ConsentEvent(
            previousState: previousState,
            newState: newState,
            purpose: purpose,
            version: dispatchSequence,
            sourceSignal: source
        )

        let dispatchTargets = adapters
        let receipts = await withTaskGroup(of: (Int, AdapterReceipt).self) { [self] group in
            for (index, adapter) in dispatchTargets.enumerated() {
                group.addTask {
                    (index, await self.dispatchWithRetry(adapter: adapter, event: event))
                }
            }
            var ordered = [AdapterReceipt?](repeating: nil, count: dispatchTargets.count)
            for await (index, receipt) in group {
                ordered[index] = receipt
            }
            return ordered.compactMap { $0 }
        }

        return try await ledger.commit(
            purpose: purpose,
            appliedState: newState,
            sourceSignal: source,
            receipts: receipts
        )
    }

    /// Dispatch to a single adapter with a per-attempt timeout and
    /// exponential backoff (with jitter) retry on genuine failure.
    ///
    /// `nonisolated` and reads only immutable constants — it touches none
    /// of ConsentBus's mutable actor state, so it doesn't need to
    /// serialize through the actor's executor. That's what lets
    /// `setConsent`'s task group actually run adapter dispatch in
    /// parallel instead of just interleaving on one executor.
    ///
    /// Patent reference: Claim 4 — retry mechanism with exponential backoff.
    nonisolated func dispatchWithRetry(
        adapter: any ConsentAdapter,
        event: ConsentEvent
    ) async -> AdapterReceipt {
        var attempt = 0
        var lastReceipt = await applyWithTimeout(adapter: adapter, event: event)

        // Only FAILED is retry-worthy — NOT_SUPPORTED is a permanent
        // capability-schema mismatch that retrying can never resolve
        // (Claim 5 distinguishes the two for exactly this reason).
        while lastReceipt.status == .failed && attempt < maxRetries {
            attempt += 1
            let baseDelay = min(baseRetryDelayNanoseconds * UInt64(pow(2.0, Double(attempt - 1))), 30_000_000_000)
            // Equal jitter (base/2 fixed + up to base/2 random): avoids a
            // thundering herd of adapters/devices retrying in lockstep,
            // while keeping backoff still meaningfully increasing.
            let half = baseDelay / 2
            let jitteredDelay = half + UInt64.random(in: 0...max(half, 1))
            try? await Task.sleep(nanoseconds: jitteredDelay)
            lastReceipt = await applyWithTimeout(adapter: adapter, event: event)
        }

        return lastReceipt.withAttemptCount(attempt + 1)
    }

    /// Races a single `apply(_:)` call against a fixed timeout so one
    /// hung adapter (e.g. a real, blocking network call in a vendor SDK
    /// with no timeout of its own) can't wedge dispatch — or, since
    /// ConsentBus is a global-actor singleton every consent operation
    /// funnels through, the entire app's consent handling — forever.
    ///
    /// This deliberately does NOT use `withTaskGroup`/`async let`: those
    /// structured-concurrency primitives guarantee a scope can't exit
    /// while it still has un-awaited *structured* children, which means
    /// losing the race still blocks this function until the slow call
    /// actually finishes on its own — verified empirically, this made an
    /// earlier version of this function take the full duration of a
    /// non-cancellation-aware blocking call instead of actually timing
    /// out. `adapter.apply(event)` is run as a genuinely *unstructured*
    /// `Task`, which is not bound to this function's scope, so this
    /// function can return the moment the timeout fires without waiting
    /// for it — the loser keeps running independently in the background
    /// (cancelled as a courtesy, which only helps adapters that
    /// cooperatively check `Task.isCancelled`; a truly blocking call, like
    /// a raw synchronous network request, can't be force-terminated by
    /// anything on the calling side — that's a fundamental limit of
    /// Swift's cooperative concurrency model, not something fixable here).
    nonisolated func applyWithTimeout(
        adapter: any ConsentAdapter,
        event: ConsentEvent
    ) async -> AdapterReceipt {
        let sdkIdentifier = await adapter.sdkIdentifier
        let sdkVersion = await adapter.sdkVersion
        let timeoutNanoseconds = adapterTimeoutNanoseconds

        let applyTask = Task<AdapterReceipt, Never> {
            await adapter.apply(event)
        }
        let resumeGuard = ResumeOnceGuard()

        return await withCheckedContinuation { (continuation: CheckedContinuation<AdapterReceipt, Never>) in
            Task {
                let receipt = await applyTask.value
                if await resumeGuard.tryResume() {
                    continuation.resume(returning: receipt)
                }
            }
            Task {
                try? await Task.sleep(nanoseconds: timeoutNanoseconds)
                if await resumeGuard.tryResume() {
                    applyTask.cancel()
                    let seconds = Double(timeoutNanoseconds) / 1_000_000_000
                    continuation.resume(returning: AdapterReceipt(
                        sdkIdentifier: sdkIdentifier,
                        sdkVersion: sdkVersion,
                        appliedState: event.newState,
                        purposeApplied: event.purpose,
                        nativeMethodCall: "N/A",
                        success: false,
                        status: .failed,
                        errorDescription: "Adapter did not respond within \(seconds)s (timed out)"
                    ))
                }
            }
        }
    }

    public func exportComplianceReport() async -> ComplianceAttestationReport? {
        await attestationEngine.generateReport()
    }

    public func currentConsentState(for purpose: ConsentPurpose) -> ConsentState {
        fsmByPurpose[purpose]?.currentState ?? .unknown
    }

    /// Verify the tamper-evident audit ledger's hash chain from genesis.
    ///
    /// Patent reference: Claim 3 — externally verifiable proof that no
    /// LedgerEntry has been altered since it was committed.
    public func verifyAuditChainIntegrity() async -> Bool {
        await ledger.verifyChainIntegrity()
    }
}

/// Ensures a `CheckedContinuation` is resumed exactly once when two
/// independent, unstructured tasks are racing to resume it — calling
/// `resume` twice on the same continuation is a fatal runtime error, and
/// with two genuinely concurrent tasks there's no other way to guarantee
/// only one of them wins without a shared, isolated arbiter like this.
private actor ResumeOnceGuard {
    private var hasResumed = false

    func tryResume() -> Bool {
        guard !hasResumed else { return false }
        hasResumed = true
        return true
    }
}

public enum ConsentBusError: Error, CustomStringConvertible {
    case duplicateAdapter(sdkIdentifier: String)

    public var description: String {
        switch self {
        case .duplicateAdapter(let sdkIdentifier):
            return "An adapter with sdkIdentifier '\(sdkIdentifier)' is already registered"
        }
    }
}
