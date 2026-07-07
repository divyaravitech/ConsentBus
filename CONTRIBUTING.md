# Contributing to ConsentBus

Thanks for considering a contribution. The most common contribution is a new SDK adapter — here's how to add one.

## Adding a new SDK adapter

Follow the pattern in [`FirebaseConsentAdapterExample.swift`](Sources/ConsentBus/Adapters/FirebaseConsentAdapterExample.swift) and the stub adapters (`MetaAudienceNetworkAdapter.swift`, `AppsFlyerAdapter.swift`, `MixpanelAdapter.swift`, `UnityAdsAdapter.swift`) in [`Sources/ConsentBus/Adapters/`](Sources/ConsentBus/Adapters/).

### 1. Implement `ConsentAdapter`

Create `Sources/ConsentBus/Adapters/<VendorName>Adapter.swift` as a `public actor` conforming to [`ConsentAdapter`](Sources/ConsentBus/Adapters/ConsentAdapter.swift):

```swift
public actor MyVendorAdapter: ConsentAdapter {
    public let sdkIdentifier = "com.myvendor.sdk"
    public let sdkVersion: String
    public let capabilitySchema = ConsentCapabilitySchema(
        sdkIdentifier: "com.myvendor.sdk",
        supportedPurposes: [/* ... */]
    )

    public init(sdkVersion: String = "1.0.0") {
        self.sdkVersion = sdkVersion
    }

    public func apply(_ event: ConsentEvent) async -> AdapterReceipt {
        guard capabilitySchema.supports(event.purpose) else {
            return receiptForUnsupportedPurpose(event)
        }
        // ...
    }
}
```

`sdkIdentifier` should be the vendor's reverse-domain package/bundle identifier. `sdkVersion` should, in a real (non-stub) adapter, be read from the wrapped SDK's own runtime metadata rather than hardcoded — see the comments in the reference adapters for examples.

### 2. Declare the `capabilitySchema`

List exactly the `ConsentPurpose` cases (see [`ConsentState.swift`](Sources/ConsentBus/Core/ConsentState.swift)) your vendor SDK's consent API actually controls. Don't over-declare — if the SDK doesn't have a way to restrict a given purpose, leave it out of `supportedPurposes`. The `capabilitySchema.supports(_:)` guard at the top of `apply(_:)` automatically returns a `NOT_SUPPORTED` receipt for anything outside the schema, which keeps it out of the `ComplianceCoverageScore` denominator (see Claim 5 in the patent application, referenced in the code comments) — this is different from `FAILED`, and matters for downstream compliance reporting.

### 3. Return an `AdapterReceipt` with the correct `nativeMethodCall`

Inside `apply(_:)`, call the vendor SDK's real consent API and return an `AdapterReceipt` with:
- `nativeMethodCall` — a string describing exactly which native API call was made (e.g. `"Analytics.setConsent([adPersonalization: denied])"`). This is what shows up in the exported compliance report, so it should be accurate and specific, not a placeholder.
- `success` / `status` — `.applied` with `success: true` on success, `.failed` with `success: false` and an `errorDescription` on a genuine failure. Don't use `.failed` for anything the SDK structurally doesn't support — use `receiptForUnsupportedPurpose(event)` for that instead.

If you're contributing a **stub** (no real vendor SDK dependency added to `Package.swift`), keep the `applyTo<Vendor>` helper private and add a comment showing the real API call that should replace it, exactly as the existing stub adapters do.

## Tests

If you're adding new logic beyond a straightforward adapter (e.g. touching `ConsentBus.swift`, `AuditLedger.swift`, or `ComplianceAttestationEngine.swift`), add or update tests in `Tests/ConsentBusTests/ConsentBusTests.swift`. Run `swift test` before opening a PR.

## Pull requests

PRs are welcome. Please keep adapter PRs scoped to a single vendor SDK.
