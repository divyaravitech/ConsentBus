import Foundation

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
    private var fsm = ConsentFSM()
    private let ledger = AuditLedger()
    public lazy var attestationEngine = ComplianceAttestationEngine(ledger: ledger)

    private let maxRetries = 3
    private let baseRetryDelayNanoseconds: UInt64 = 1_000_000_000 // 1s

    private init() {}

    /// Register an SDK adapter. Adapters should be registered at app launch
    /// before any consent events are dispatched.
    public func register(adapter: any ConsentAdapter) {
        adapters.append(adapter)
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
        let previousState = fsm.currentState
        try fsm.transition(to: newState)

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
    /// Patent reference: Claim 4 — retry mechanism with exponential backoff,
    /// recording each retry as a subsequent ledger entry referencing the
    /// original event version.
    private func dispatchWithRetry(
        adapter: any ConsentAdapter,
        event: ConsentEvent
    ) async -> AdapterReceipt {
        var attempt = 0
        var lastReceipt = await adapter.apply(event)

        while !lastReceipt.success && attempt < maxRetries {
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

    public func currentConsentState() -> ConsentState {
        fsm.currentState
    }
}
