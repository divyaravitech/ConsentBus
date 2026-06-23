import Foundation
import Crypto

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

        let receiptsData = try JSONEncoder().encode(receipts)
        let receiptsString = String(data: receiptsData, encoding: .utf8) ?? ""
        let payload = "\(lastHash)|\(version)|\(appliedState.rawValue)|\(receiptsString)"

        let mac = HMAC<SHA256>.authenticationCode(
            for: Data(payload.utf8),
            using: hmacKey
        )
        let currentHash = Data(mac).map { String(format: "%02hhx", $0) }.joined()

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
    public func verifyChainIntegrity() -> Bool {
        var expectedPrevious = "GENESIS"
        for entry in entries {
            guard entry.previousHash == expectedPrevious else { return false }
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
}
