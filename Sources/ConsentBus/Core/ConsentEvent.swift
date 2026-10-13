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

/// The outcome of an SDK adapter's attempt to apply a consent event, as
/// reported by the adapter itself. ConsentBus records it faithfully; it does
/// not independently verify that the wrapped SDK actually honored the change.
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
    /// Total number of times the adapter's `apply(_:)` was called before
    /// this receipt was produced — 1 means it concluded (successfully or
    /// not) on the first attempt; >1 means ConsentBus retried it under the
    /// exponential-backoff policy before arriving at this final
    /// outcome. Adapters never set this themselves — it always defaults to
    /// 1 from the public initializer; ConsentBus.dispatchWithRetry attaches
    /// the real count once dispatch (including any retries) concludes.
    public private(set) var attemptCount: Int

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
        self.attemptCount = 1
    }

    /// Internal-only: attach the real attempt count once dispatch (with
    /// any retries) has concluded, preserving every other field — notably
    /// `appliedAt` — exactly as the adapter produced it.
    func withAttemptCount(_ attemptCount: Int) -> AdapterReceipt {
        var copy = self
        copy.attemptCount = attemptCount
        return copy
    }
}

/// Propagation outcome classification. `notSupported` (the adapter declared
/// the purpose outside its capability schema — permanent, never retried) is
/// deliberately distinct from `failed` (the adapter was asked and didn't, or
/// couldn't be confirmed to, apply it), so the coverage score can exclude
/// structural gaps instead of counting them as failures.
public enum PropagationStatus: String, Codable, Sendable {
    case applied = "APPLIED"
    case failed = "FAILED"
    case notSupported = "NOT_SUPPORTED"
    /// Reserved. ConsentBus does not currently produce this status.
    case rollback = "ROLLBACK"
}
