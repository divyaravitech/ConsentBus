import Foundation

/// Stub adapter for Meta Audience Network.
///
/// NOTE: This is a skeleton/example only — it does not import the real
/// FBAudienceNetwork/FBSDKCoreKit SDKs. Replace the stubbed
/// `applyToAudienceNetwork` call with the real Meta consent API invocation
/// when wiring up an actual Meta Audience Network dependency.
///
/// Patent reference: Section IV (Claim Family A) and Section X
/// (Reference Implementation).
public actor MetaAudienceNetworkAdapter: ConsentAdapter {
    public let sdkIdentifier = "com.facebook.audiencenetwork"
    public let sdkVersion: String

    public let capabilitySchema = ConsentCapabilitySchema(
        sdkIdentifier: "com.facebook.audiencenetwork",
        supportedPurposes: [.adStorage, .adPersonalization, .adUserData]
    )

    public init(sdkVersion: String = "6.15.1") {
        // In a real adapter, read this from the SDK's own runtime metadata,
        // e.g. FBAdSettings' version constant — never hardcode in production.
        self.sdkVersion = sdkVersion
    }

    public func apply(_ event: ConsentEvent) async -> AdapterReceipt {
        guard capabilitySchema.supports(event.purpose) else {
            return receiptForUnsupportedPurpose(event)
        }

        let methodCall = applyToAudienceNetwork(state: event.newState, purpose: event.purpose)

        return AdapterReceipt(
            sdkIdentifier: sdkIdentifier,
            sdkVersion: sdkVersion,
            appliedState: event.newState,
            purposeApplied: event.purpose,
            nativeMethodCall: methodCall,
            success: true,
            status: .applied
        )
    }

    /// Stubbed native call — replace with the real Meta consent API call,
    /// e.g.:
    /// FBSDKSettings.shared.isAdvertiserTrackingEnabled = granted
    /// FBSDKSettings.shared.setDataProcessingOptions(granted ? [] : ["LDU"])
    private func applyToAudienceNetwork(state: ConsentState, purpose: ConsentPurpose) -> String {
        let granted = (state == .granted)
        return "FBSDKSettings.shared.setDataProcessingOptions(\(purpose.rawValue): \(granted ? "[]" : "[\"LDU\"]"))"
    }
}
