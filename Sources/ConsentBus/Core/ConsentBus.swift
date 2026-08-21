import Foundation
import CryptoKit

/// The central consent broker: a process-resident singleton that dispatches
/// consent events to all registered SDK adapters within a single serialized
/// execution context, eliminating race conditions in consent propagation.
///
/// Patent reference: Application No. 64/087,949, Claims 1, 2, 10 —
/// consent broker singleton executing on a dedicated serial execution
/// context such that no SDK adapter dispatch operation is initiated while
/// a prior dispatch operation is in progress.
@globalActor
public actor ConsentBus {
    public static let shared = ConsentBus()

    private var adapters: [any ConsentAdapter] = []
    private var fsmByPurpose: [ConsentPurpose: ConsentFSM] = [:]
    private let ledger: AuditLedger
    public let attestationEngine: ComplianceAttestationEngine

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
    public func register(adapter: any ConsentAdapter) async throws {
        adapters.append(adapter)

        for (purpose, fsm) in fsmByPurpose where fsm.currentState != .unknown {
            let event = ConsentEvent(
                previousState: fsm.currentState,
                newState: fsm.currentState,
                purpose: purpose,
                version: await ledger.currentVersion() + 1,
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
    /// dispatch the resulting ConsentEvent to every registered adapter
    /// within a single serialized pass, collecting AdapterReceipts and
    /// committing them to the tamper-evident audit ledger.
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

        let version = await ledger.currentVersion() + 1
        let event = ConsentEvent(
            previousState: previousState,
            newState: newState,
            purpose: purpose,
            version: version,
            sourceSignal: source
        )

        var receipts: [AdapterReceipt] = []
        for adapter in adapters {
            let receipt = await dispatchWithRetry(adapter: adapter, event: event)
            receipts.append(receipt)
        }

        return try await ledger.commit(
            purpose: purpose,
            appliedState: newState,
            sourceSignal: source,
            receipts: receipts
        )
    }

    /// Dispatch to a single adapter with exponential backoff retry on failure.
    ///
    /// Patent reference: Claim 4 — retry mechanism with exponential backoff.
    func dispatchWithRetry(
        adapter: any ConsentAdapter,
        event: ConsentEvent
    ) async -> AdapterReceipt {
        var attempt = 0
        var lastReceipt = await adapter.apply(event)

        // Only FAILED is retry-worthy — NOT_SUPPORTED is a permanent
        // capability-schema mismatch that retrying can never resolve
        // (Claim 5 distinguishes the two for exactly this reason).
        while lastReceipt.status == .failed && attempt < maxRetries {
            attempt += 1
            let delay = baseRetryDelayNanoseconds * UInt64(pow(2.0, Double(attempt - 1)))
            try? await Task.sleep(nanoseconds: min(delay, 30_000_000_000))
            lastReceipt = await adapter.apply(event)
        }

        return lastReceipt
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
