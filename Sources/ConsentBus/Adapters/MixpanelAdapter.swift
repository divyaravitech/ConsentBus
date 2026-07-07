import Foundation

/// Stub adapter for Mixpanel.
///
/// NOTE: This is a skeleton/example only — it does not import the real
/// Mixpanel SDK. Replace the stubbed `applyToMixpanel` call with the real
/// Mixpanel consent API invocation when wiring up an actual Mixpanel
/// dependency.
///
/// Patent reference: Section IV (Claim Family A) and Section X
/// (Reference Implementation).
public actor MixpanelAdapter: ConsentAdapter {
    public let sdkIdentifier = "com.mixpanel.ios-sdk"
    public let sdkVersion: String

    public let capabilitySchema = ConsentCapabilitySchema(
        sdkIdentifier: "com.mixpanel.ios-sdk",
        supportedPurposes: [.analyticsStorage, .personalization]
    )

    public init(sdkVersion: String = "4.2.0") {
        // In a real adapter, read this from the SDK's own runtime metadata,
        // e.g. Mixpanel's exposed lib version constant — never hardcode in
        // production.
        self.sdkVersion = sdkVersion
    }

    public func apply(_ event: ConsentEvent) async -> AdapterReceipt {
        guard capabilitySchema.supports(event.purpose) else {
            return receiptForUnsupportedPurpose(event)
        }

        let methodCall = applyToMixpanel(state: event.newState, purpose: event.purpose)

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

    /// Stubbed native call — replace with the real Mixpanel consent API
    /// call, e.g.:
    /// if granted {
    ///     Mixpanel.mainInstance().optInTracking()
    /// } else {
    ///     Mixpanel.mainInstance().optOutTracking()
    /// }
    private func applyToMixpanel(state: ConsentState, purpose: ConsentPurpose) -> String {
        let granted = (state == .granted)
        return granted
            ? "Mixpanel.mainInstance().optInTracking()"
            : "Mixpanel.mainInstance().optOutTracking()"
    }
}
