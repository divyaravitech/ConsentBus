import ConsentBus
import Foundation

// MARK: - Mock SDK adapters demonstrating the three propagation outcomes
// ConsentBus's patent (Claim 5) distinguishes APPLIED, FAILED, and
// NOT_SUPPORTED so a compliance report can tell "this SDK doesn't do that"
// apart from "this SDK failed to honor the restriction."

actor AlwaysSucceedsAdapter: ConsentAdapter {
    let sdkIdentifier = "com.example.mock.alwayssucceeds"
    let sdkVersion = "1.4.2"
    let capabilitySchema = ConsentCapabilitySchema(
        sdkIdentifier: "com.example.mock.alwayssucceeds",
        supportedPurposes: Set(ConsentPurpose.allCases)
    )

    func apply(_ event: ConsentEvent) async -> AdapterReceipt {
        guard capabilitySchema.supports(event.purpose) else {
            return receiptForUnsupportedPurpose(event)
        }
        return AdapterReceipt(
            sdkIdentifier: sdkIdentifier,
            sdkVersion: sdkVersion,
            appliedState: event.newState,
            purposeApplied: event.purpose,
            nativeMethodCall: "MockSDK.setConsent(.\(event.purpose.rawValue), \(event.newState.rawValue))",
            success: true,
            status: .applied
        )
    }
}

actor AlwaysFailsAdapter: ConsentAdapter {
    let sdkIdentifier = "com.example.mock.alwaysfails"
    let sdkVersion = "0.8.0-beta"
    let capabilitySchema = ConsentCapabilitySchema(
        sdkIdentifier: "com.example.mock.alwaysfails",
        supportedPurposes: Set(ConsentPurpose.allCases)
    )

    func apply(_ event: ConsentEvent) async -> AdapterReceipt {
        guard capabilitySchema.supports(event.purpose) else {
            return receiptForUnsupportedPurpose(event)
        }
        return AdapterReceipt(
            sdkIdentifier: sdkIdentifier,
            sdkVersion: sdkVersion,
            appliedState: event.newState,
            purposeApplied: event.purpose,
            nativeMethodCall: "N/A",
            success: false,
            status: .failed,
            errorDescription: "Simulated network timeout while applying consent"
        )
    }
}

/// Declares support for only half of ConsentBus's purpose taxonomy —
/// deliberately excluding analyticsStorage and adPersonalization, the two
/// purposes this demo revokes, so both dispatches show a NOT_SUPPORTED
/// receipt distinct from AlwaysFailsAdapter's FAILED receipt.
actor PartialSupportAdapter: ConsentAdapter {
    let sdkIdentifier = "com.example.mock.partialsupport"
    let sdkVersion = "3.1.0"
    let capabilitySchema = ConsentCapabilitySchema(
        sdkIdentifier: "com.example.mock.partialsupport",
        supportedPurposes: [.locationPrecise, .locationApproximate, .personalization, .measurement, .guardianMediated]
    )

    func apply(_ event: ConsentEvent) async -> AdapterReceipt {
        guard capabilitySchema.supports(event.purpose) else {
            return receiptForUnsupportedPurpose(event)
        }
        return AdapterReceipt(
            sdkIdentifier: sdkIdentifier,
            sdkVersion: sdkVersion,
            appliedState: event.newState,
            purposeApplied: event.purpose,
            nativeMethodCall: "PartialSDK.apply(\(event.purpose.rawValue))",
            success: true,
            status: .applied
        )
    }
}

// MARK: - Demo output helpers

func section(_ title: String) {
    print("\n" + String(repeating: "─", count: 72))
    print(title)
    print(String(repeating: "─", count: 72))
}

func printReceipts(_ entry: LedgerEntry) {
    for receipt in entry.receipts {
        let icon: String
        switch receipt.status {
        case .applied: icon = "[APPLIED]     "
        case .failed: icon = "[FAILED]      "
        case .notSupported: icon = "[NOT_SUPPORTED]"
        case .rollback: icon = "[ROLLBACK]    "
        }
        print("  \(icon) \(receipt.sdkIdentifier) (v\(receipt.sdkVersion))")
        print("                   → \(receipt.nativeMethodCall)")
        if let error = receipt.errorDescription {
            print("                   ⚠ \(error)")
        }
    }
}

// MARK: - Demo

section("ConsentBus Demo — Patent Pending, US Provisional Application No. 64/087,949")

print("""

The problem: when a user revokes consent, 5–20+ third-party SDKs each need
to be notified through different, vendor-specific APIs — with no standard
way to prove, after the fact, which SDKs actually received and honored it.

This demo registers 3 mock SDKs with different behaviors and shows how
ConsentBus dispatches a single consent change to all of them atomically,
collects a structured receipt from each, and produces a tamper-evident,
cryptographically verifiable audit trail.
""")

section("⚠ This demo writes to your REAL Keychain and disk")

print("""

ConsentBus.shared is the real production singleton, not a sandboxed demo
instance — so the moment this demo touches it below, it persists a real
HMAC key and an Ed25519 signing key to your login Keychain, and writes a
real ledger file to disk. Specifically:

  Keychain service : \(AuditLedgerPersistence.default.keychainService)
  Ledger file      : \(AuditLedgerPersistence.default.entriesFileURL.path)

This is intentional — it's what proves persistence actually survives a
relaunch (run this demo twice and watch consentVersion/chainProof keep
growing in Step 4). But it means running this demo leaves real artifacts
on your machine. To remove them afterward:

  rm -rf "\(AuditLedgerPersistence.default.entriesFileURL.deletingLastPathComponent().path)"
  security delete-generic-password -s "\(AuditLedgerPersistence.default.keychainService)" -a "hmac-key"
  security delete-generic-password -s "\(AuditLedgerPersistence.default.keychainService)" -a "ed25519-signing-key"
""")

section("Step 1 — Registering SDK Adapters")

let alwaysSucceeds = AlwaysSucceedsAdapter()
let alwaysFails = AlwaysFailsAdapter()
let partialSupport = PartialSupportAdapter()

try await ConsentBus.shared.register(adapter: alwaysSucceeds)
try await ConsentBus.shared.register(adapter: alwaysFails)
try await ConsentBus.shared.register(adapter: partialSupport)

print("  Registered: \(alwaysSucceeds.sdkIdentifier)  — always applies consent successfully")
print("  Registered: \(alwaysFails.sdkIdentifier)     — always fails to apply consent")
print("  Registered: \(partialSupport.sdkIdentifier)  — supports only 5 of 10 declared consent purposes")

section("Step 2 — Revoking analyticsStorage")

do {
    let entry = try await ConsentBus.shared.setConsent(.revoked, purpose: .analyticsStorage, source: .userUI)
    print("  Ledger entry #\(entry.version) committed. Adapter receipts:")
    printReceipts(entry)
} catch {
    print("  Failed to set consent: \(error)")
}

section("Step 3 — Revoking adPersonalization")

do {
    let entry = try await ConsentBus.shared.setConsent(.revoked, purpose: .adPersonalization, source: .userUI)
    print("  Ledger entry #\(entry.version) committed. Adapter receipts:")
    printReceipts(entry)

    print("""

    Notice: "com.example.mock.partialsupport" returned NOT_SUPPORTED, not
    FAILED — it declared adPersonalization outside its capability schema.
    ConsentBus keeps that distinct from a genuine failure, so it's excluded
    from the compliance coverage denominator entirely (Claim 5).
    """)
} catch {
    print("  Failed to set consent: \(error)")
}

section("Step 4 — Compliance Attestation Report")

if let report = await ConsentBus.shared.exportComplianceReport() {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    encoder.dateEncodingStrategy = .iso8601
    let data = try! encoder.encode(report)
    print(String(data: data, encoding: .utf8) ?? "<encoding failed>")
} else {
    print("  No report available.")
}

section("Step 5 — Verifying Tamper-Evident Chain Integrity")

let isValid = await ConsentBus.shared.verifyAuditChainIntegrity()
if isValid {
    print("""
      VALID — every ledger entry's HMAC-SHA256 hash correctly chains to the
      one before it, and each entry's hash matches a fresh recomputation
      from its stored content. No tampering detected.
    """)
} else {
    print("  INVALID — the audit ledger has been tampered with.")
}

section("Done")
