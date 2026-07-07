import Foundation

/// Stub adapter for Unity Ads.
///
/// NOTE: This is a skeleton/example only — it does not import the real
/// UnityAds SDK. Replace the stubbed `applyToUnityAds` call with the real
/// Unity Ads consent API invocation when wiring up an actual Unity Ads
/// dependency.
///
/// Patent reference: Section IV (Claim Family A) and Section X
/// (Reference Implementation).
public actor UnityAdsAdapter: ConsentAdapter {
    public let sdkIdentifier = "com.unity3d.ads"
    public let sdkVersion: String

    public let capabilitySchema = ConsentCapabilitySchema(
        sdkIdentifier: "com.unity3d.ads",
        supportedPurposes: [.adStorage, .adPersonalization, .guardianMediated]
    )

    public init(sdkVersion: String = "4.9.3") {
        // In a real adapter, read this from the SDK's own runtime metadata,
        // e.g. UnityAds.getVersion() — never hardcode in production.
        self.sdkVersion = sdkVersion
    }

    public func apply(_ event: ConsentEvent) async -> AdapterReceipt {
        guard capabilitySchema.supports(event.purpose) else {
            return receiptForUnsupportedPurpose(event)
        }

        let methodCall = applyToUnityAds(state: event.newState, purpose: event.purpose)

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

    /// Stubbed native call — replace with the real Unity Ads consent API
    /// call, e.g.:
    /// let gdprMetaData = MetaData()
    /// gdprMetaData.set("gdpr.consent", granted)
    /// gdprMetaData.commit()
    private func applyToUnityAds(state: ConsentState, purpose: ConsentPurpose) -> String {
        let granted = (state == .granted)
        return "MetaData().set(\"gdpr.consent\", \(granted)).commit() // \(purpose.rawValue)"
    }
}
