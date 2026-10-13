## Research Paper

📄 **[ConsentBus: Atomic Cross-SDK Privacy Consent Propagation 
with Cryptographic Audit for Mobile Applications](https://doi.org/10.2139/ssrn.7087439)**  
*Divya Ravi — SSRN Preprint · DOI: 10.2139/ssrn.7087439 · July 2026*

# ConsentBus

**Coordinated, tamper-evident consent propagation across heterogeneous mobile SDKs.**

[![CI](https://github.com/divyaravitech/ConsentBus/actions/workflows/ci.yml/badge.svg)](https://github.com/divyaravitech/ConsentBus/actions/workflows/ci.yml)
[![Swift](https://img.shields.io/badge/Swift-5.9-orange.svg)](https://swift.org)
[![Platform](https://img.shields.io/badge/platform-iOS%2016%2B-blue.svg)](https://developer.apple.com)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Patent Pending](https://img.shields.io/badge/Patent-Pending-yellow.svg)](#patent-status)

## The Problem

Modern mobile apps embed 5–20+ third-party SDKs — analytics, advertising, attribution, crash reporting. When a user changes their privacy consent, there is no standard way to propagate that change to every SDK in a coordinated, recorded way. Each vendor exposes a different API with different failure modes, and consent-management tools typically leave it to you to verify that consent actually reached each SDK.

This creates:
- **Race conditions** — SDKs may continue collecting data in the window between consent revocation and notification
- **Silent failures** — no way to distinguish "SDK doesn't support this consent category" from "SDK failed to honor the restriction"
- **No audit trail** — no verifiable proof of compliance for regulators or internal audit

## What ConsentBus Does

ConsentBus is a lightweight Swift package that sits between your app's consent UI and your third-party SDKs:

- **Serialized, coordinated dispatch** — consent operations run strictly one at a time, and each change is delivered to every registered SDK adapter in a single coordinated pass (adapters run concurrently within the pass, each with its own timeout so one hung adapter can't block the rest). This narrows — it cannot eliminate — the window in which SDKs disagree about consent
- **Structured receipts** — every SDK adapter returns a receipt recording what it reports it applied, when, and via which native API call. Receipts are the adapter's own report; ConsentBus does not independently verify that the SDK honored the change (see [THREAT_MODEL.md](THREAT_MODEL.md))
- **Hash-chained, persisted audit ledger** — every consent event is committed to an HMAC-SHA256 chain that detects edits by anyone without the key, with the key in the Keychain and entries on disk, so the record — and the consent decisions in it — survive app relaunch
- **Capability-aware dispatch** — each adapter declares which consent purposes it supports; ConsentBus distinguishes `NOT_SUPPORTED` from `FAILED`, giving you a precise `ComplianceCoverageScore`
- **Digitally signed compliance reports** — every `ComplianceAttestationReport` carries an Ed25519 signature that anyone holding the public key (`ConsentBus.shared.compliancePublicKey`) can verify, so a report altered after export is detectable. The signature proves integrity since signing — not that the signing key belongs to a genuine device, which needs separate key-provenance evidence (see [THREAT_MODEL.md](THREAT_MODEL.md))
- **Late-joining adapters get synced automatically** — an SDK registered after a consent decision was already made (common for lazily-initialized SDKs) is replayed the existing per-purpose state before `register(adapter:)` returns, instead of silently running under its own default

## What this does and doesn't guarantee

ConsentBus gives you an ordered, recorded, integrity-checked account of what each adapter *reported* when you changed consent. It does **not** prove that a third-party SDK actually stopped collecting data, it is not a consent-management platform, and it is not a compliance guarantee. [THREAT_MODEL.md](THREAT_MODEL.md) lists exactly what is and isn't covered — read it before relying on a report as evidence.

## Quick Start

```swift
import ConsentBus

// Register adapters at app launch. Adapters registered later (e.g. a
// lazily-initialized SDK) are automatically synced to whatever consent
// state was already established, so they never run on stale defaults.
try await ConsentBus.shared.register(adapter: FirebaseConsentAdapterExample())
try await ConsentBus.shared.register(adapter: MetaAudienceNetworkAdapter())
try await ConsentBus.shared.register(adapter: AppsFlyerAdapter())

// Propagate a consent change to all registered SDKs in one coordinated pass
let entry = try await ConsentBus.shared.setConsent(.revoked, purpose: .adPersonalization, source: .userUI)

// Export a signed compliance report
let report = await ConsentBus.shared.exportComplianceReport()

// Verify the tamper-evident audit chain
let isValid = await ConsentBus.shared.verifyAuditChainIntegrity()

// Independently verify a report's signature — an auditor only needs the
// report and this public key, never anything from the device itself
if let report {
    let publicKey = ConsentBus.shared.compliancePublicKey
    let signatureIsValid = ComplianceAttestationEngine.verify(report, publicKey: publicKey)
}
```

Running the bundled demo target (`swift run ConsentBusDemo`) produces output like this:

```
────────────────────────────────────────────────────────────────────────
Step 3 — Revoking adPersonalization
────────────────────────────────────────────────────────────────────────
  Ledger entry #2 committed. Adapter receipts:
  [APPLIED]      com.example.mock.alwayssucceeds (v1.4.2)
                   → MockSDK.setConsent(.adPersonalization, revoked)
  [FAILED]       com.example.mock.alwaysfails (v0.8.0-beta)
                   → N/A
                   ⚠ Simulated network timeout while applying consent
  [NOT_SUPPORTED] com.example.mock.partialsupport (v3.1.0)
                   → N/A
                   ⚠ Purpose adPersonalization not in declared schema

────────────────────────────────────────────────────────────────────────
Step 6 — Verifying Tamper-Evident Chain Integrity
────────────────────────────────────────────────────────────────────────
  VALID — every ledger entry's HMAC-SHA256 hash correctly chains to the
  one before it, and each entry's hash matches a fresh recomputation
  from its stored content. No tampering detected.
```

## Live Compliance Report

[**View live demo report →**](https://divyaravitech.github.io/ConsentBus/compliance-report.html)

The report above shows a real ConsentBus run demonstrating:
- **Three-way outcome classification** — APPLIED / FAILED / NOT_SUPPORTED
- **Coverage score** — computed as APPLIED ÷ (APPLIED + FAILED), excluding NOT_SUPPORTED from the denominator
- **Tamper-evident HMAC-SHA256 chain** — every entry links cryptographically to the previous one
- **Exportable ComplianceAttestationReport** — machine-readable JSON, digitally signable for regulators

> Run it yourself: `swift run ConsentBusDemo`

## Supported SDK Adapters

| SDK | analyticsStorage | adStorage | adPersonalization | adUserData | personalization | measurement |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| [Firebase](Sources/ConsentBus/Adapters/FirebaseConsentAdapterExample.swift) | ✅ | ✅ | ✅ | | | |
| [Meta Audience Network](Sources/ConsentBus/Adapters/MetaAudienceNetworkAdapter.swift) | | ✅ | ✅ | ✅ | | |
| [AppsFlyer](Sources/ConsentBus/Adapters/AppsFlyerAdapter.swift) | ✅ | | | ✅ | | ✅ |
| [Mixpanel](Sources/ConsentBus/Adapters/MixpanelAdapter.swift) | ✅ | | | | ✅ | |

**All of these adapters are currently stubs** — they compile and return realistic `AdapterReceipt`s, but none of them calls a real vendor SDK yet, so nothing in this repository has yet been exercised against a real SDK. Each stub file has a comment showing the real native call it should make. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to wire one up for real.

## How It Works

```
   Application Layer (consent UI, CMP, OS privacy signals)
                          │
                          │ setConsent(.revoked, purpose: .adPersonalization, source: .userUI)
                          ▼
   ┌──────────────────────────────────────────────────────────┐
   │              ConsentBus (singleton, serial actor)         │
   │                                                            │
   │   1. Per-purpose FSM validates the transition              │
   │        .granted -> .revoked  ✓                              │
   │                                                            │
   │   2. Dispatch to every registered adapter concurrently, so  │
   │      all of them receive this consent change in one pass    │
   │      unit — each with a per-adapter timeout and exponential- │
   │      backoff-with-jitter retry on genuine failure            │
   │        Firebase  ──▶ APPLIED                               │
   │        Meta      ──▶ APPLIED                               │
   │        AppsFlyer ──▶ FAILED (retried 3x, then recorded)    │
   │        Mixpanel  ──▶ NOT_SUPPORTED (outside schema)         │
   │                                                            │
   │   3. Commit an HMAC-SHA256-chained LedgerEntry              │
   │        hash(entry N) = HMAC(hash(entry N-1) | receipts)     │
   └──────────────────────────────────────────────────────────┘
                          │
                          ▼
          Tamper-evident Audit Ledger (hash-chained)
                          │
                          ▼
        ComplianceAttestationReport (exportable, JSON, signed)
        coverageScore = APPLIED / (APPLIED + FAILED) × 100
        NOT_SUPPORTED excluded from the denominator entirely
```

## Compliance Report Example

```json
{
  "chainProof" : [
    "7f75d2d29286602e7b1e4742c553d45e57d1dddc9acbbf030014c7b2d6fb0ae3",
    "e0493ca6071541c92f352309ea7f412a77a4a5fc318bdad17eac1b66407882a1"
  ],
  "consentChangedAt" : "2026-07-07T16:23:50Z",
  "consentVersion" : 2,
  "coverageScore" : 50,
  "generatedAt" : "2026-07-07T16:23:51Z",
  "propagationTable" : [
    {
      "sdkIdentifier" : "com.google.firebase",
      "sdkVersion" : "10.21.0",
      "status" : "APPLIED",
      "nativeMethodCall" : "Analytics.setConsent([adPersonalization: denied])"
    },
    {
      "sdkIdentifier" : "com.appsflyer.sdk",
      "sdkVersion" : "6.14.2",
      "status" : "FAILED",
      "nativeMethodCall" : "N/A"
    },
    {
      "sdkIdentifier" : "com.mixpanel.ios-sdk",
      "sdkVersion" : "4.2.0",
      "status" : "NOT_SUPPORTED",
      "nativeMethodCall" : "N/A"
    }
  ],
  "signature" : "1jNwLFrFPEbbyJEpAIlZ33jXJSjwHrSWikxr9/UDE4mTOtUl1A716RY1HPHpFpnlysafvYsP7YTZsE5YfjAgBA=="
}
```

`coverageScore` excludes `NOT_SUPPORTED` entries from the denominator entirely — Mixpanel doesn't declare `adPersonalization` in its capability schema, so it isn't penalized as a compliance failure the way AppsFlyer's genuine `FAILED` receipt is.

`consentChangedAt` is when the consent change actually happened; `generatedAt` is when this report artifact was exported, which can be considerably later if a report is requested for audit purposes well after the fact.

`signature` is an Ed25519 signature over every other field, computed with a private key that never leaves the device's Keychain. Verify it with `ComplianceAttestationEngine.verify(report, publicKey:)` and the public key from `ConsentBus.shared.compliancePublicKey` — an auditor needs only the report and that public key, never anything secret from the device.

## Status

This is an early-stage reference implementation accompanying a filed patent application. Firebase, Meta Audience Network, AppsFlyer, and Mixpanel adapters exist, but all of them are stubs that don't call a real vendor SDK (see the adapter table above). Community contributions to wire them up to real vendor SDKs, and to add further adapters, are welcome.

**Roadmap:**
- [x] Meta Audience Network adapter (stub)
- [x] AppsFlyer adapter (stub)
- [x] Mixpanel adapter (stub)
- [ ] Android (Kotlin) reference implementation
- [ ] Per-intent OS privacy declaration schema alignment subsystem
- [ ] Behavioral verification (network proxy observation)

## Patent Status

This project is the subject of a filed U.S. provisional patent application (Application No. 64/087,949, filed June 11, 2026). The code is licensed under Apache License 2.0, which includes an explicit patent grant (Section 3): using, modifying, and distributing this codebase is licensed under the applicable patent claims, not just copyright. See [LICENSE](LICENSE) for the exact scope, and its closing note for a plain-language summary of what that grant does and doesn't cover.

## Contributing

Adapters should implement the `ConsentAdapter` protocol in `Sources/ConsentBus/Adapters/ConsentAdapter.swift`. See `FirebaseConsentAdapterExample.swift` for the expected pattern. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full step-by-step guide, including how the patent/license interact for contributors. PRs welcome.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
