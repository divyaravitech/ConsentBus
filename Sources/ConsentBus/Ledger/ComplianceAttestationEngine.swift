import Foundation
import CryptoKit

/// A single row in the compliance attestation report's propagation table.
public struct PropagationStatusEntry: Codable, Sendable {
    public let sdkIdentifier: String
    public let sdkVersion: String
    public let status: PropagationStatus
    public let nativeMethodCall: String

    public init(sdkIdentifier: String, sdkVersion: String, status: PropagationStatus, nativeMethodCall: String) {
        self.sdkIdentifier = sdkIdentifier
        self.sdkVersion = sdkVersion
        self.status = status
        self.nativeMethodCall = nativeMethodCall
    }
}

/// The fields a ComplianceAttestationReport's signature is computed over.
/// Kept separate from the signed report itself since a struct obviously
/// can't include a signature over its own not-yet-computed signature field.
private struct UnsignedReportPayload: Codable {
    let consentVersion: UInt64
    let consentChangedAt: Date
    let generatedAt: Date
    let propagationTable: [PropagationStatusEntry]
    let coverageScore: Double
    let chainProof: [String]
}

/// Machine-readable, exportable compliance artifact.
///
/// Patent reference: Claim Family D, Claim 7 — ComplianceAttestationReport
/// comprising versioned snapshot, per-SDK PropagationStatusTable,
/// ComplianceCoverageScore, ChainProof, and digital signature.
public struct ComplianceAttestationReport: Codable, Sendable {
    public let consentVersion: UInt64
    /// When the underlying consent change this report describes actually
    /// happened — distinct from `generatedAt`, which is when this report
    /// artifact was exported and may be considerably later (a report can
    /// be requested for audit purposes well after the fact).
    public let consentChangedAt: Date
    public let generatedAt: Date
    public let propagationTable: [PropagationStatusEntry]
    public let coverageScore: Double
    public let chainProof: [String]
    /// Ed25519 signature (raw 64 bytes, base64-encoded) over the
    /// deterministic JSON encoding of every field above. Verify with
    /// `ComplianceAttestationEngine.verify(_:publicKey:)` — an auditor only
    /// needs this report plus the public key from
    /// `ConsentBus.shared.compliancePublicKey`, never the device's secret
    /// signing key.
    public let signature: String

    public init(
        consentVersion: UInt64,
        consentChangedAt: Date,
        generatedAt: Date,
        propagationTable: [PropagationStatusEntry],
        coverageScore: Double,
        chainProof: [String],
        signature: String
    ) {
        self.consentVersion = consentVersion
        self.consentChangedAt = consentChangedAt
        self.generatedAt = generatedAt
        self.propagationTable = propagationTable
        self.coverageScore = coverageScore
        self.chainProof = chainProof
        self.signature = signature
    }
}

/// Generates and independently verifies signed ComplianceAttestationReport
/// artifacts from the AuditLedger.
///
/// Signing uses Ed25519 (asymmetric), not HMAC — a symmetric HMAC would
/// only be verifiable by someone who also holds the same secret used to
/// produce it, which defeats the point of proving authenticity to a third
/// party (a regulator or auditor) who must never be handed the device's
/// signing secret.
public actor ComplianceAttestationEngine {
    private let ledger: AuditLedger
    private let signingKey: Curve25519.Signing.PrivateKey

    /// The public key auditors use to verify reports this engine signs.
    /// Safe to distribute; it cannot be used to forge a signature.
    public nonisolated var publicKey: Curve25519.Signing.PublicKey {
        signingKey.publicKey
    }

    public init(ledger: AuditLedger, signingKey: Curve25519.Signing.PrivateKey) {
        self.ledger = ledger
        self.signingKey = signingKey
    }

    /// Generate a signed attestation report for the most recent ledger entry.
    public func generateReport() async -> ComplianceAttestationReport? {
        let entries = await ledger.allEntries()
        guard let latest = entries.last else { return nil }

        let table = latest.receipts.map {
            PropagationStatusEntry(
                sdkIdentifier: $0.sdkIdentifier,
                sdkVersion: $0.sdkVersion,
                status: $0.status,
                nativeMethodCall: $0.nativeMethodCall
            )
        }

        let payload = UnsignedReportPayload(
            consentVersion: latest.version,
            consentChangedAt: latest.timestamp,
            generatedAt: Date(),
            propagationTable: table,
            coverageScore: Self.computeCoverageScore(receipts: latest.receipts),
            chainProof: entries.map { $0.currentHash }
        )

        // If signing genuinely fails, do NOT ship a report with a blank/
        // broken signature that merely *looks* trustworthy — a report
        // whose entire value proposition is its signature is worse than
        // no report at all if that signature is silently fake. Treat it
        // the same as "nothing to report."
        guard let signature = try? signingKey.signature(for: Self.canonicalPayloadData(payload)) else {
            return nil
        }

        return ComplianceAttestationReport(
            consentVersion: payload.consentVersion,
            consentChangedAt: payload.consentChangedAt,
            generatedAt: payload.generatedAt,
            propagationTable: payload.propagationTable,
            coverageScore: payload.coverageScore,
            chainProof: payload.chainProof,
            signature: signature.base64EncodedString()
        )
    }

    /// Verify a report's signature against a public key, independent of the
    /// device or process that generated it — this is a `static` function
    /// precisely so an auditor's tooling can call it with just the report
    /// JSON and the distributed public key, no live ConsentBus required.
    public static func verify(_ report: ComplianceAttestationReport, publicKey: Curve25519.Signing.PublicKey) -> Bool {
        guard let signatureData = Data(base64Encoded: report.signature) else { return false }
        let payload = UnsignedReportPayload(
            consentVersion: report.consentVersion,
            consentChangedAt: report.consentChangedAt,
            generatedAt: report.generatedAt,
            propagationTable: report.propagationTable,
            coverageScore: report.coverageScore,
            chainProof: report.chainProof
        )
        return publicKey.isValidSignature(signatureData, for: canonicalPayloadData(payload))
    }

    /// ComplianceCoverageScore = APPLIED / (APPLIED + FAILED) * 100,
    /// excluding NOT_SUPPORTED from the denominator.
    ///
    /// Patent reference: Claim 5, paragraph [0035].
    static func computeCoverageScore(receipts: [AdapterReceipt]) -> Double {
        let applicable = receipts.filter { $0.status == .applied || $0.status == .failed }
        guard !applicable.isEmpty else { return 100.0 }
        let appliedCount = applicable.filter { $0.status == .applied }.count
        return (Double(appliedCount) / Double(applicable.count)) * 100.0
    }

    /// .sortedKeys + a fixed date strategy are required so the same payload
    /// always encodes to the same bytes — otherwise signing and later
    /// verification could compute over different byte sequences for
    /// identical content and every signature would spuriously fail.
    private static func canonicalPayloadData(_ payload: UnsignedReportPayload) -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        encoder.dateEncodingStrategy = .iso8601
        return (try? encoder.encode(payload)) ?? Data()
    }
}
