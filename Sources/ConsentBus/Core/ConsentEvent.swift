import Foundation

/// A consent state change to be propagated to all registered SDK adapters.
public struct ConsentEvent: Codable, Sendable {
    public let id: UUID
    public let timestamp: Date
    public let previousState: ConsentState
    public let newState: ConsentState
    public let purpose: ConsentPurpose
    public let version: UInt64
    public let sourceSignal: ConsentSource

    public init(
        previousState: ConsentState,
        newState: ConsentState,
        purpose: ConsentPurpose,
        version: UInt64,
        sourceSignal: ConsentSource
    ) {
        self.id = UUID()
        self.timestamp = Date()
        self.previousState = previousState
        self.newState = newState
        self.purpose = purpose
        self.version = version
        self.sourceSignal = sourceSignal
    }
}

/// The outcome of an SDK adapter's attempt to apply a consent event.
///
/// Patent reference: Claim 1 — structured AdapterReceipt comprising
/// vendor identifier, SDK version, consent state confirmation,
/// timestamp, native API method, and success indicator.
public struct AdapterReceipt: Codable, Sendable {
    public let sdkIdentifier: String
    public let sdkVersion: String
    public let appliedState: ConsentState
    public let purposeApplied: ConsentPurpose
    public let nativeMethodCall: String
    public let appliedAt: Date
    public let success: Bool
    public let status: PropagationStatus
    public let errorDescription: String?

    public init(
        sdkIdentifier: String,
        sdkVersion: String,
        appliedState: ConsentState,
        purposeApplied: ConsentPurpose,
        nativeMethodCall: String,
        success: Bool,
        status: PropagationStatus,
        errorDescription: String? = nil
    ) {
        self.sdkIdentifier = sdkIdentifier
        self.sdkVersion = sdkVersion
        self.appliedState = appliedState
        self.purposeApplied = purposeApplied
        self.nativeMethodCall = nativeMethodCall
        self.appliedAt = Date()
        self.success = success
        self.status = status
        self.errorDescription = errorDescription
    }
}

/// Three-way propagation outcome classification.
///
/// Patent reference: Claim 5 — NOT_SUPPORTED is semantically distinct
/// from FAILED, enabling precise ComplianceCoverageScore computation.
public enum PropagationStatus: String, Codable, Sendable {
    case applied = "APPLIED"
    case failed = "FAILED"
    case notSupported = "NOT_SUPPORTED"
    case rollback = "ROLLBACK"
}
