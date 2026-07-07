import Foundation
import CryptoKit

/// A single immutable entry in the tamper-evident consent audit ledger.
///
/// Patent reference: Claim 1, Claim 3 — receipt-chained tamper-evident
/// LedgerEntry whose hash incorporates the preceding entry's hash and
/// all collected AdapterReceipts.
public struct LedgerEntry: Codable, Sendable {
    public let version: UInt64
    public let timestamp: Date
    public let purpose: ConsentPurpose
    public let appliedState: ConsentState
    public let sourceSignal: ConsentSource
    public let receipts: [AdapterReceipt]
    public let previousHash: String
    public let currentHash: String
}

/// Tamper-evident, hash-chained audit ledger.
///
/// Each commit incorporates the previous entry's hash and the full set
/// of AdapterReceipts collected during that propagation event into an
/// HMAC-SHA256 computation, per Claim 3.
public actor AuditLedger {
    private var version: UInt64 = 0
    private var lastHash: String = "GENESIS"
    private var entries: [LedgerEntry] = []
    private let hmacKey: SymmetricKey

    public init(hmacKey: SymmetricKey = SymmetricKey(size: .bits256)) {
        self.hmacKey = hmacKey
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
