import Foundation

/// A single row in the compliance attestation report's propagation table.
public struct PropagationStatusEntry: Codable, Sendable {
    public let sdkIdentifier: String
    public let sdkVersion: String
    public let status: PropagationStatus
    public let nativeMethodCall: String
}

/// Machine-readable, exportable compliance artifact.
///
/// Patent reference: Claim Family D, Claim 7 — ComplianceAttestationReport
/// comprising versioned snapshot, per-SDK PropagationStatusTable,
/// ComplianceCoverageScore, ChainProof, and digital signature.
public struct ComplianceAttestationReport: Codable, Sendable {
    public let consentVersion: UInt64
    public let generatedAt: Date
    public let propagationTable: [PropagationStatusEntry]
    public let coverageScore: Double
    public let chainProof: [String]
}

/// Generates ComplianceAttestationReport artifacts from the AuditLedger.
public actor ComplianceAttestationEngine {
    private let ledger: AuditLedger

    public init(ledger: AuditLedger) {
        self.ledger = ledger
    }

    /// Generate an attestation report for the most recent ledger entry.
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

        let coverageScore = Self.computeCoverageScore(receipts: latest.receipts)
        let chainProof = entries.map { $0.currentHash }

        return ComplianceAttestationReport(
            consentVersion: latest.version,
            generatedAt: Date(),
            propagationTable: table,
            coverageScore: coverageScore,
            chainProof: chainProof
        )
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
}
