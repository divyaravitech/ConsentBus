import Foundation
import CryptoKit

/// A single immutable entry in the consent audit ledger. Its hash
/// incorporates the preceding entry's hash and every AdapterReceipt
/// collected for that consent change.
public struct LedgerEntry: Codable, Sendable {
    public let version: UInt64
    public let timestamp: Date
    public let purpose: ConsentPurpose
    public let appliedState: ConsentState
    public let sourceSignal: ConsentSource
    public let receipts: [AdapterReceipt]
    public let previousHash: String
    public let currentHash: String

    public init(
        version: UInt64,
        timestamp: Date,
        purpose: ConsentPurpose,
        appliedState: ConsentState,
        sourceSignal: ConsentSource,
        receipts: [AdapterReceipt],
        previousHash: String,
        currentHash: String
    ) {
        self.version = version
        self.timestamp = timestamp
        self.purpose = purpose
        self.appliedState = appliedState
        self.sourceSignal = sourceSignal
        self.receipts = receipts
        self.previousHash = previousHash
        self.currentHash = currentHash
    }
}

/// Tamper-evident, hash-chained audit ledger.
///
/// Each commit incorporates the previous entry's hash and the full set
/// of AdapterReceipts collected during that propagation event into an
/// HMAC-SHA256 computation.
///
/// What "tamper-evident" means here, precisely: the chain detects edits to
/// any committed entry by anyone who does NOT hold the HMAC key. It does
/// not defend against a party who holds the key (they can recompute the
/// whole chain), and nothing external anchors the chain's head, so
/// truncating the newest entries or restoring an older copy of the ledger
/// is not detectable from the ledger alone. See THREAT_MODEL.md.
public actor AuditLedger {
    private var version: UInt64
    private var lastHash: String
    private var entries: [LedgerEntry]
    private let hmacKey: SymmetricKey
    private let entryStore: AuditLedgerEntryFileStore?

    /// The most recent applied state per purpose among the entries this
    /// ledger was restored with (empty for a fresh ledger). `ConsentBus`
    /// uses it at launch to rebuild its per-purpose state machines, so a
    /// consent decision made in a previous session is still in force — and
    /// is re-applied to adapters as they register — after a relaunch.
    let restoredConsentStates: [ConsentPurpose: ConsentState]

    /// `restoringEntries` must be a previously committed, in-order chain
    /// produced with the same `hmacKey`.
    init(
        hmacKey: SymmetricKey,
        restoringEntries: [LedgerEntry] = [],
        entryStore: AuditLedgerEntryFileStore? = nil
    ) {
        self.hmacKey = hmacKey
        self.entryStore = entryStore
        self.entries = restoringEntries
        self.version = restoringEntries.last?.version ?? 0
        self.lastHash = restoringEntries.last?.currentHash ?? "GENESIS"
        self.restoredConsentStates = Self.latestStates(in: restoringEntries)
    }

    /// Creates a transient, in-memory-only ledger: a fresh random HMAC key,
    /// no persistence. Entries are lost when this instance deallocates.
    /// Suitable for tests and short-lived usage — not for production
    /// compliance evidence, which needs `init(persistence:)`.
    public init() {
        self.hmacKey = SymmetricKey(size: .bits256)
        self.entryStore = nil
        self.entries = []
        self.version = 0
        self.lastHash = "GENESIS"
        self.restoredConsentStates = [:]
    }

    /// Creates a ledger whose HMAC key is stored in the Keychain and whose
    /// committed entries are persisted to disk, so the audit trail survives
    /// app relaunch. This is what `ConsentBus.shared` uses.
    public init(persistence: AuditLedgerPersistence) throws {
        let keyStore = KeychainKeyStore(service: persistence.keychainService, account: persistence.keychainAccount)
        let keyData = try keyStore.loadOrCreate { Data(SymmetricKey(size: .bits256).withUnsafeBytes { Array($0) }) }
        let entryStore = AuditLedgerEntryFileStore(fileURL: persistence.entriesFileURL)
        let loaded = try entryStore.load()

        self.hmacKey = SymmetricKey(data: keyData)
        self.entryStore = entryStore
        self.entries = loaded
        self.version = loaded.last?.version ?? 0
        self.lastHash = loaded.last?.currentHash ?? "GENESIS"
        self.restoredConsentStates = Self.latestStates(in: loaded)
    }

    private static func latestStates(in entries: [LedgerEntry]) -> [ConsentPurpose: ConsentState] {
        var states: [ConsentPurpose: ConsentState] = [:]
        for entry in entries {
            states[entry.purpose] = entry.appliedState
        }
        return states
    }

    /// Commit a new ledger entry, computing its hash from the previous
    /// entry's hash, the version, applied state, and serialized receipts.
    @discardableResult
    public func commit(
        purpose: ConsentPurpose,
        appliedState: ConsentState,
        sourceSignal: ConsentSource,
        receipts: [AdapterReceipt]
    ) throws -> LedgerEntry {
        version += 1

        let currentHash = try computeHash(
            previousHash: lastHash,
            version: version,
            appliedState: appliedState,
            receipts: receipts
        )

        let entry = LedgerEntry(
            version: version,
            timestamp: Date(),
            purpose: purpose,
            appliedState: appliedState,
            sourceSignal: sourceSignal,
            receipts: receipts,
            previousHash: lastHash,
            currentHash: currentHash
        )

        entries.append(entry)
        lastHash = currentHash

        // Persist if configured. Note: the consent change has already been
        // dispatched to adapters by the time commit() is called, so a write
        // failure here can't roll that back — it surfaces as a thrown error
        // so the caller can detect/retry a durability gap, not to prevent
        // the (already-happened) consent change from being recorded
        // in-memory for this process's lifetime.
        try entryStore?.save(entries)

        return entry
    }

    /// Verify the integrity of the entire hash chain from genesis.
    ///
    /// Recomputes each entry's HMAC from its stored content (not just the
    /// previousHash/currentHash linkage) so that post-commit tampering with
    /// any field — including a nested AdapterReceipt — is detected.
    public func verifyChainIntegrity() -> Bool {
        var expectedPrevious = "GENESIS"
        for entry in entries {
            guard entry.previousHash == expectedPrevious else { return false }
            guard let recomputed = try? computeHash(
                previousHash: entry.previousHash,
                version: entry.version,
                appliedState: entry.appliedState,
                receipts: entry.receipts
            ), recomputed == entry.currentHash else { return false }
            expectedPrevious = entry.currentHash
        }
        return true
    }

    public func allEntries() -> [LedgerEntry] {
        entries
    }

    public func currentVersion() -> UInt64 {
        version
    }

    private func computeHash(
        previousHash: String,
        version: UInt64,
        appliedState: ConsentState,
        receipts: [AdapterReceipt]
    ) throws -> String {
        // .sortedKeys is required: JSONEncoder does not otherwise guarantee
        // stable key ordering across separate encode() calls, which would
        // make the HMAC non-reproducible between commit() and a later
        // verifyChainIntegrity() recomputation of the same content.
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let receiptsData = try encoder.encode(receipts)
        let receiptsString = String(data: receiptsData, encoding: .utf8) ?? ""
        let payload = "\(previousHash)|\(version)|\(appliedState.rawValue)|\(receiptsString)"

        let mac = HMAC<SHA256>.authenticationCode(
            for: Data(payload.utf8),
            using: hmacKey
        )
        return Data(mac).map { String(format: "%02hhx", $0) }.joined()
    }

    /// Test-only hook: overwrite a committed entry's receipts without
    /// recomputing its hash, to simulate post-commit tampering in tests.
    /// Internal access only — not part of the public API surface.
    func _testOnly_corruptEntry(at index: Int, receipts: [AdapterReceipt]) {
        let existing = entries[index]
        entries[index] = LedgerEntry(
            version: existing.version,
            timestamp: existing.timestamp,
            purpose: existing.purpose,
            appliedState: existing.appliedState,
            sourceSignal: existing.sourceSignal,
            receipts: receipts,
            previousHash: existing.previousHash,
            currentHash: existing.currentHash
        )
    }
}
