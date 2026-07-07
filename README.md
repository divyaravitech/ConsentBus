# ConsentBus

**Atomic, cryptographically verifiable consent propagation across heterogeneous mobile SDKs.**

[![Swift](https://img.shields.io/badge/Swift-5.9-orange.svg)](https://swift.org)
[![Platform](https://img.shields.io/badge/platform-iOS%2016%2B-blue.svg)](https://developer.apple.com)
[![Patent Pending](https://img.shields.io/badge/Patent-Pending-yellow.svg)](#patent-status)

## The Problem

Modern mobile apps embed 5–20+ third-party SDKs — analytics, advertising, attribution, crash reporting. When a user changes their privacy consent, there is no standard way to propagate that change to all SDKs simultaneously and verifiably. Each vendor exposes a different API, with different failure modes, and **no system today can cryptographically prove which SDKs actually received and applied a given consent state.**

This creates:
- **Race conditions** — SDKs may continue collecting data in the window between consent revocation and notification
- **Silent failures** — no way to distinguish "SDK doesn't support this consent category" from "SDK failed to honor the restriction"
- **No audit trail** — no verifiable proof of compliance for regulators or internal audit

## What ConsentBus Does

ConsentBus is a lightweight Swift package that sits between your app's consent UI and your third-party SDKs:

- **Atomic dispatch** — a single serialized broker propagates consent to every registered SDK adapter in one execution pass, eliminating partial-propagation race conditions
- **Cryptographic receipts** — every SDK adapter returns a structured, signed receipt confirming exactly what was applied, when, and via which native API call
- **Hash-chained audit ledger** — every consent event is committed to a tamper-evident HMAC-SHA256 chain, producing a verifiable compliance record
- **Capability-aware dispatch** — each adapter declares which consent purposes it supports; ConsentBus distinguishes `NOT_SUPPORTED` from `FAILED`, giving you a precise `ComplianceCoverageScore`
- **Exportable compliance reports** — generate a signed, machine-readable attestation artifact for your DPO or regulatory audit, without needing device access

## Quick Start

```swift
import ConsentBus

// Register adapters at app launch
await ConsentBus.shared.register(adapter: FirebaseConsentAdapterExample())
await ConsentBus.shared.register(adapter: MetaAudienceNetworkAdapter())
await ConsentBus.shared.register(adapter: AppsFlyerAdapter())

// Propagate a consent change atomically to all registered SDKs
let entry = try await ConsentBus.shared.setConsent(.revoked, purpose: .adPersonalization, source: .userUI)

// Export a compliance report
let report = await ConsentBus.shared.exportComplianceReport()

// Verify the tamper-evident audit chain
let isValid = await ConsentBus.shared.verifyAuditChainIntegrity()
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
Step 5 — Verifying Tamper-Evident Chain Integrity
────────────────────────────────────────────────────────────────────────
  VALID — every ledger entry's HMAC-SHA256 hash correctly chains to the
  one before it, and each entry's hash matches a fresh recomputation
  from its stored content. No tampering detected.
```

## Live Compliance Report

[**View live demo report →**](https://divyaravitech.github.io/ConsentBus/compliance-report.html)

The report above shows a real ConsentBus run demonstrating:
- **Three-way outcome classification** — APPLIED / FAILED / NOT_SUPPORTED
- **Coverage score** — computed as APPLIED ÷ (APPLIED + FAILED), excluding NOT_SUPPORTED from the denominator (Patent Claim 5)
- **Tamper-evident HMAC-SHA256 chain** — every entry links cryptographically to the previous one
- **Exportable ComplianceAttestationReport** — machine-readable JSON, digitally signable for regulators

> Run it yourself: `swift run ConsentBusDemo`

## Supported SDK Adapters

| SDK | analyticsStorage | adStorage | adPersonalization | adUserData | personalization | measurement | guardianMediated |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| [Firebase](Sources/ConsentBus/Adapters/FirebaseConsentAdapterExample.swift) | ✅ | ✅ | ✅ | | | | |
| [Meta Audience Network](Sources/ConsentBus/Adapters/MetaAudienceNetworkAdapter.swift) | | ✅ | ✅ | ✅ | | | |
| [AppsFlyer](Sources/ConsentBus/Adapters/AppsFlyerAdapter.swift) | ✅ | | | ✅ | | ✅ | |
| [Mixpanel](Sources/ConsentBus/Adapters/MixpanelAdapter.swift) | ✅ | | | | ✅ | | |
| [Unity Ads](Sources/ConsentBus/Adapters/UnityAdsAdapter.swift) | | ✅ | ✅ | | | | ✅ |

All adapters other than Firebase's are currently **stubs** — they compile and return realistic `AdapterReceipt`s but don't call a real vendor SDK yet. Each stub file has a comment showing the real native call it should make. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to wire one up for real.

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
   │   2. Dispatch to every registered adapter, one pass,       │
   │      with exponential-backoff retry on genuine failures    │
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
  ]
}
```

`coverageScore` excludes `NOT_SUPPORTED` entries from the denominator entirely — Mixpanel doesn't declare `adPersonalization` in its capability schema, so it isn't penalized as a compliance failure the way AppsFlyer's genuine `FAILED` receipt is.

## Status

This is an early-stage reference implementation accompanying a filed patent application. Firebase, Meta Audience Network, AppsFlyer, Mixpanel, and Unity Ads adapters exist as reference implementations (Firebase is a fuller worked example; the other four are stubs — see the adapter table above). Community contributions to wire the stubs up to real vendor SDKs, and to add further adapters, are welcome.

**Roadmap:**
- [x] Meta Audience Network adapter (stub)
- [x] AppsFlyer adapter (stub)
- [x] Mixpanel adapter (stub)
- [x] Unity Ads adapter (stub)
- [ ] Android (Kotlin) reference implementation
- [ ] Per-intent OS privacy declaration schema alignment subsystem
- [ ] Behavioral verification (network proxy observation)

## Patent Status

This project's core architecture — atomic SDK consent dispatch, receipt-chained audit ledger, capability negotiation protocol, and compliance attestation engine — is described in a filed U.S. provisional patent application (Application No. 64/087,949, filed June 11, 2026). The code in this repository is provided under the MIT license below; the patent covers the underlying method and system.

## Contributing

Adapters should implement the `ConsentAdapter` protocol in `Sources/ConsentBus/Adapters/ConsentAdapter.swift`. See `FirebaseConsentAdapterExample.swift` for the expected pattern. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full step-by-step guide. PRs welcome.

## License

MIT — see [LICENSE](LICENSE).
