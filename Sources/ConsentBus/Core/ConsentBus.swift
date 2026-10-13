import Foundation
import CryptoKit

/// The central consent broker: a process-resident singleton that serializes
/// consent operations and delivers each consent change to every registered
/// SDK adapter, recording each adapter's self-reported outcome in a
/// tamper-evident audit ledger.
///
/// **Ordering.** Consent operations (`setConsent`, and the state replay that
/// `register(adapter:)` performs) are mutually exclusive: one operation's
/// dispatch phase never overlaps another's, and each operation observes the
/// effects of every earlier one. Within a single operation, adapters are
/// contacted concurrently. Swift actors are reentrant across `await`, so
/// this exclusion is enforced explicitly by `operationGate` — it is not a
/// free property of being an actor.
///
/// **Limits.** ConsentBus narrows — it cannot eliminate — the window in
/// which SDKs disagree about consent, and an adapter's receipt is that
/// adapter's own report, not independent proof the SDK honored the change.
/// See THREAT_MODEL.md for exactly what is and isn't guaranteed.
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
    /// Makes consent operations mutually exclusive (see the type docs).
    /// Cost: head-of-line blocking — a slow adapter delays every queued
    /// operation, bounded by (maxRetries + 1) timeouts plus backoff.
    private let operationGate = SerialOperationGate()
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

    /// Designated initializer. Internal so tests can build isolated,
    /// in-memory instances instead of sharing (and polluting) the
    /// process-wide singleton and its real Keychain/disk state.
    init(
        ledger: AuditLedger,
        signingKey: Curve25519.Signing.PrivateKey,
        isPersistenceDegraded: Bool
    ) {
        self.ledger = ledger
        self.attestationEngine = ComplianceAttestationEngine(ledger: ledger, signingKey: signingKey)
        self.isPersistenceDegraded = isPersistenceDegraded
        // Consent decisions from a previous launch are still in force. Without
        // this, a relaunch silently reset every purpose to `.unknown`, so
        // adapters registering at launch were never re-synced and SDKs that
        // reset to their own defaults each launch (commonly opt-in) resumed
        // collecting data the user had already revoked.
        self.fsmByPurpose = Self.restoredStateMachines(from: ledger)
    }

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

        self.ledger = ledger
        self.attestationEngine = ComplianceAttestationEngine(ledger: ledger, signingKey: signingKey)
        self.isPersistenceDegraded = persistenceDegraded
        self.fsmByPurpose = Self.restoredStateMachines(from: ledger)
    }

    private static func restoredStateMachines(from ledger: AuditLedger) -> [ConsentPurpose: ConsentFSM] {
        ledger.restoredConsentStates.mapValues { ConsentFSM(restoring: $0) }
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
    /// That includes decisions restored from a previous launch's ledger.
    ///
    /// Throws `ConsentBusError.duplicateAdapter` if an adapter with the
    /// same `sdkIdentifier` is already registered, rather than silently
    /// double-dispatching every future consent change to it.
    public func register(adapter: any ConsentAdapter) async throws {
        try await exclusively { try await self.performRegistration(of: adapter) }
    }

    private func performRegistration(of adapter: any ConsentAdapter) async throws {
        let newIdentifier = await adapter.sdkIdentifier

        // Check-and-insert with no `await` in between: this is what
        // actually makes it race-free against a reentrant concurrent
        // register() call, not just the fact that a check happens at all.
        guard !registeredIdentifiers.contains(newIdentifier) else {
            throw ConsentBusError.duplicateAdapter(sdkIdentifier: newIdentifier)
        }
        registeredIdentifiers.insert(newIdentifier)
        adapters.append(adapter)

        // Sorted: dictionary order is randomized per launch, and a ledger
        // whose replay order differs run to run is needlessly hard to audit.
        let establishedStates = fsmByPurpose
            .filter { $0.value.currentState != .unknown }
            .sorted { $0.key.rawValue < $1.key.rawValue }

        for (purpose, fsm) in establishedStates {
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

    /// Validate the requested transition, then deliver the resulting
    /// ConsentEvent to every registered adapter — concurrently within this
    /// operation — collecting each adapter's receipt and committing them to
    /// the audit ledger. Operations are mutually exclusive: if another
    /// consent operation is in flight, this one waits its turn.
    @discardableResult
    public func setConsent(
        _ newState: ConsentState,
        purpose: ConsentPurpose,
        source: ConsentSource
    ) async throws -> LedgerEntry {
        try await exclusively {
            try await self.performSetConsent(newState, purpose: purpose, source: source)
        }
    }

    private func performSetConsent(
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

    /// Runs `operation` while holding `operationGate`, releasing it on both
    /// the success and the throwing path.
    private func exclusively<T>(_ operation: () async throws -> T) async rethrows -> T {
        await operationGate.acquire()
        do {
            let result = try await operation()
            await operationGate.release()
            return result
        } catch {
            await operationGate.release()
            throw error
        }
    }

    /// Dispatch to a single adapter with a per-attempt timeout and
    /// exponential backoff (with jitter) retry on genuine failure.
    ///
    /// `nonisolated` and reads only immutable constants — it touches none
    /// of ConsentBus's mutable actor state, so it doesn't need to
    /// serialize through the actor's executor. That's what lets
    /// `setConsent`'s task group actually run adapter dispatch in
    /// parallel instead of just interleaving on one executor.
    nonisolated func dispatchWithRetry(
        adapter: any ConsentAdapter,
        event: ConsentEvent
    ) async -> AdapterReceipt {
        var attempt = 0
        var lastReceipt = await applyWithTimeout(adapter: adapter, event: event)

        // Only FAILED is retry-worthy — NOT_SUPPORTED is a permanent
        // capability-schema mismatch that retrying can never resolve.
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

    /// Recompute and check the audit ledger's HMAC chain from genesis.
    ///
    /// This is an integrity check performed by the holder of the ledger's
    /// HMAC key (this device). A third party without that key cannot run it,
    /// and it cannot detect truncation of the newest entries or restoration
    /// of an older copy of the ledger. See THREAT_MODEL.md.
    public func verifyAuditChainIntegrity() async -> Bool {
        await ledger.verifyChainIntegrity()
    }
}

/// A FIFO async mutex. Swift actors are reentrant at every `await`, so two
/// consent operations on `ConsentBus` would otherwise interleave their
/// dispatch phases; this makes them strictly one-at-a-time, in arrival order.
private actor SerialOperationGate {
    private var isLocked = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func acquire() async {
        if !isLocked {
            isLocked = true
            return
        }
        await withCheckedContinuation { waiters.append($0) }
    }

    func release() {
        if waiters.isEmpty {
            isLocked = false
        } else {
            // Ownership passes directly to the next waiter; the lock never
            // becomes visible as free in between, so nobody can barge in.
            waiters.removeFirst().resume()
        }
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
