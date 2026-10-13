import Foundation
#if canImport(Security)
import Security
#endif

/// Where `AuditLedger` durably stores its HMAC key and committed entries.
///
/// Without this, the audit ledger is an in-memory convenience log that
/// vanishes the moment the process is terminated — which iOS does to
/// backgrounded apps routinely. A ledger meant to serve as real
/// regulatory/compliance evidence has to survive that.
public struct AuditLedgerPersistence: Sendable {
    public let keychainService: String
    public let keychainAccount: String
    public let entriesFileURL: URL

    public init(keychainService: String, keychainAccount: String, entriesFileURL: URL) {
        self.keychainService = keychainService
        self.keychainAccount = keychainAccount
        self.entriesFileURL = entriesFileURL
    }

    /// Keychain-backed key, entries stored under Application Support.
    /// This is what `ConsentBus.shared` uses.
    public static let `default` = AuditLedgerPersistence(
        keychainService: "com.consentbus.auditledger",
        keychainAccount: "hmac-key",
        entriesFileURL: AuditLedgerPersistence.defaultEntriesFileURL()
    )

    private static func defaultEntriesFileURL() -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        return base
            .appendingPathComponent("ConsentBus", isDirectory: true)
            .appendingPathComponent("audit-ledger.json")
    }
}

enum PersistenceError: Error, CustomStringConvertible {
    case keychain(OSStatus)
    case unexpectedKeychainData

    var description: String {
        switch self {
        case .keychain(let status):
            return "Keychain operation failed with OSStatus \(status)"
        case .unexpectedKeychainData:
            return "Keychain returned data in an unexpected format"
        }
    }
}

/// Minimal Keychain-backed store for a single secret's raw bytes. Shared by
/// AuditLedger (HMAC key) and ComplianceAttestationEngine (Ed25519 signing
/// key) — each under its own account name in the same service.
struct KeychainKeyStore {
    let service: String
    let account: String

    func loadOrCreate(generator: () -> Data) throws -> Data {
        if let existing = try load() {
            return existing
        }
        let generated = generator()
        try save(generated)
        return generated
    }

    /// Test-only cleanup so persistence tests don't leave residue in the
    /// real Keychain. Internal access only.
    func delete() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
    }

    private func load() throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data else { throw PersistenceError.unexpectedKeychainData }
            return data
        case errSecItemNotFound:
            return nil
        default:
            throw PersistenceError.keychain(status)
        }
    }

    private func save(_ data: Data) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        // Apple explicitly warns that omitting kSecAttrAccessible produces
        // unpredictable behavior across contexts (this was found the hard
        // way: it correlated with SecItemAdd failing under a bare XCTest
        // bundle on iOS Simulator, which lacks a host app's entitlements).
        // ThisDeviceOnly matters here specifically: the ledger's entries
        // live only on local disk and are never iCloud-synced, so letting
        // this key sync via iCloud Keychain to another device (the
        // non-ThisDeviceOnly variant's behavior) would be a semantic
        // mismatch — a synced key with no corresponding synced data.
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        let status = SecItemAdd(query.merging(attributes) { _, new in new } as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw PersistenceError.keychain(status)
        }
    }
}

/// Disk-backed store for committed LedgerEntry history. Rewrites the whole
/// file atomically on each commit — simple and crash-safe, at the cost of
/// O(n) I/O per commit. Adequate for a reference implementation; a
/// high-volume production deployment would want an append-only log or a
/// real database instead.
struct AuditLedgerEntryFileStore {
    let fileURL: URL

    func load() throws -> [LedgerEntry] {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return [] }
        let data = try Data(contentsOf: fileURL)
        if data.isEmpty { return [] }
        return try JSONDecoder().decode([LedgerEntry].self, from: data)
    }

    func save(_ entries: [LedgerEntry]) throws {
        let directory = fileURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let data = try encoder.encode(entries)
        try data.write(to: fileURL, options: .atomic)
    }
}
