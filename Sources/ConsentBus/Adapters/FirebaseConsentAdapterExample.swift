import Foundation

/// Reference example adapter showing the pattern other adapters should follow.
///
/// NOTE: This is a skeleton/example only — it does not import the real
/// FirebaseAnalytics SDK. Replace the stubbed `applyToFirebase` call
/// with the real `Analytics.setConsent(...)` invocation when wiring up
/// an actual Firebase dependency.
///
/// Patent reference: Section IV (Claim Family A) and Section X
/// (Reference Implementation).
public actor FirebaseConsentAdapterExample: ConsentAdapter {
    public let sdkIdentifier = "com.google.firebase"
    public let sdkVersion: String

    public let capabilitySchema = ConsentCapabilitySchema(
        sdkIdentifier: "com.google.firebase",
        supportedPurposes: [.analyticsStorage, .adStorage, .adPersonalization]
    )

    public init(sdkVersion: String = "10.21.0") {
        // In a real adapter, read this from the SDK's own runtime metadata,
        // e.g. FirebaseApp's version constant — never hardcode in production.
        self.sdkVersion = sdkVersion
    }

    public func apply(_ event: ConsentEvent) async -> AdapterReceipt {
        guard capabilitySchema.supports(event.purpose) else {
            return receiptForUnsupportedPurpose(event)
        }

        let methodCall = applyToFirebase(state: event.newState, purpose: event.purpose)

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

    /// Stubbed native call — replace with real Analytics.setConsent(...) call.
    private func applyToFirebase(state: ConsentState, purpose: ConsentPurpose) -> String {
        let granted = (state == .granted)
        // Analytics.setConsent([.analyticsStorage: granted ? .granted : .denied])
        return "Analytics.setConsent([\(purpose.rawValue): \(granted ? "granted" : "denied")])"
    }
}
