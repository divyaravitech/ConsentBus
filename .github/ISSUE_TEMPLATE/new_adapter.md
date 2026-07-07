---
name: New SDK adapter
about: Request (or propose) a ConsentAdapter for a third-party SDK
title: "Add <Vendor> adapter"
labels: help wanted
assignees: ''
---

## SDK / Vendor

- Name:
- Bundle / package identifier (reverse-domain form, e.g. `com.vendor.sdk`):
- Link to vendor's consent/privacy API docs:

## Consent purposes this SDK can control

List the `ConsentPurpose` cases (see `Sources/ConsentBus/Core/ConsentState.swift`) this SDK actually exposes a consent-restriction API for. Only list what the vendor SDK can genuinely restrict — this becomes the adapter's `capabilitySchema`.

- [ ] analyticsStorage
- [ ] adStorage
- [ ] adPersonalization
- [ ] adUserData
- [ ] functional
- [ ] locationPrecise
- [ ] locationApproximate
- [ ] personalization
- [ ] measurement
- [ ] guardianMediated

## Native consent API

What native method(s) should `apply(_:)` call to actually enforce the consent state? (Paste the real API signature if known — e.g. `Analytics.setConsent([...])`.)

## Stub or real integration?

- [ ] Stub only (no vendor SDK dependency added to `Package.swift`, matches the pattern in `MetaAudienceNetworkAdapter.swift` / `AppsFlyerAdapter.swift` / etc.)
- [ ] Real integration (adds the vendor SDK as a Package.swift dependency and calls its live API)

## Additional context

Anything else a contributor should know (SDK version constraints, platform availability, known quirks in the vendor's consent API, etc.).
