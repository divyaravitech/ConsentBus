import Foundation

/// Stub adapter for AppsFlyer.
///
/// NOTE: This is a skeleton/example only — it does not import the real
/// AppsFlyerLib SDK. Replace the stubbed `applyToAppsFlyer` call with the
/// real AppsFlyer consent API invocation when wiring up an actual
/// AppsFlyer dependency.
///
/// Patent reference: Section IV (Claim Family A) and Section X
/// (Reference Implementation).
public actor AppsFlyerAdapter: ConsentAdapter {
    public let sdkIdentifier = "com.appsflyer.sdk"
    public let sdkVersion: String

    public let capabilitySchema = ConsentCapabilitySchema(
        sdkIdentifier: "com.appsflyer.sdk",
        supportedPurposes: [.analyticsStorage, .adUserData, .measurement]
    )

    public init(sdkVersion: String = "6.14.2") {
        // In a real adapter, read this from the SDK's own runtime metadata,
        // e.g. AppsFlyerLib.shared().getSDKVersion() — never hardcode in
        // production.
        self.sdkVersion = sdkVersion
    }

    public func apply(_ event: ConsentEvent) async -> AdapterReceipt {
        guard capabilitySchema.supports(event.purpose) else {
            return receiptForUnsupportedPurpose(event)
        }

        let methodCall = applyToAppsFlyer(state: event.newState, purpose: event.purpose)

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

    /// Stubbed native call — replace with the real AppsFlyer consent API
    /// call, e.g.:
    /// let consent = AppsFlyerConsent(
    ///     isUserSubjectToGDPR: true,
    ///     hasConsentForDataUsage: granted,
    ///     hasConsentForAdsPersonalization: granted,
    ///     hasConsentForAdStorage: granted
    /// )
    /// AppsFlyerLib.shared().setConsentData(consent)
    private func applyToAppsFlyer(state: ConsentState, purpose: ConsentPurpose) -> String {
        let granted = (state == .granted)
        return "AppsFlyerLib.shared().setConsentData(AppsFlyerConsent(hasConsentForDataUsage: \(granted), purpose: \(purpose.rawValue)))"
    }
}
