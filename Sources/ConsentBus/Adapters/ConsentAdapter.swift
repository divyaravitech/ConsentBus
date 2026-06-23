import Foundation

/// Machine-readable declaration of which consent purposes an SDK adapter supports.
///
/// Patent reference: Claim Family B — Capability Declaration and
/// Negotiation Protocol (Claim 5).
public struct ConsentCapabilitySchema: Codable, Sendable {
    public let sdkIdentifier: String
    public let supportedPurposes: Set<ConsentPurpose>

    public init(sdkIdentifier: String, supportedPurposes: Set<ConsentPurpose>) {
        self.sdkIdentifier = sdkIdentifier
        self.supportedPurposes = supportedPurposes
    }

    public func supports(_ purpose: ConsentPurpose) -> Bool {
        supportedPurposes.contains(purpose)
    }
}

/// The normalized interface every third-party SDK adapter must implement.
///
/// Adapters wrap a vendor-specific consent API behind this common protocol,
/// enabling the ConsentBus broker to dispatch consent events without
/// knowledge of each SDK's proprietary implementation.
///
/// Patent reference: Section VIII — Adapter Protocol.
public protocol ConsentAdapter: Actor {
    /// Vendor-issued package/bundle identifier for the wrapped SDK.
    var sdkIdentifier: String { get }

    /// Capability schema declared at registration time.
    var capabilitySchema: ConsentCapabilitySchema { get }

    /// The current runtime version of the wrapped SDK, read from the
    /// SDK's own metadata (not hardcoded) to support rollback detection.
    var sdkVersion: String { get }

    /// Apply a consent event to the wrapped SDK and return a structured receipt.
    func apply(_ event: ConsentEvent) async -> AdapterReceipt
}

public extension ConsentAdapter {
    /// Default implementation: returns a NOT_SUPPORTED receipt for purposes
    /// outside the adapter's declared capability schema, per Claim 5.
    func receiptForUnsupportedPurpose(_ event: ConsentEvent) -> AdapterReceipt {
        AdapterReceipt(
            sdkIdentifier: sdkIdentifier,
            sdkVersion: sdkVersion,
            appliedState: event.newState,
            purposeApplied: event.purpose,
            nativeMethodCall: "N/A",
            success: false,
            status: .notSupported,
            errorDescription: "Purpose \(event.purpose.rawValue) not in declared schema"
        )
    }
}
