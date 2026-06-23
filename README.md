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

// Propagate a consent change atomically to all registered SDKs
try await ConsentBus.shared.setConsent(.revoked, purpose: .adPersonalization, source: .userUI)

// Export a compliance report
let report = await ConsentBus.shared.exportComplianceReport()
```

## Architecture

```
Application Layer (UI, CMP, OS privacy signals)
        │
        ▼
ConsentBus Broker (singleton, serial execution context)
   ├── ConsentState FSM
   ├── Adapter Registry
   └── Audit Ledger (hash-chained)
        │
        ▼
SDK Adapter Layer (Firebase, Meta, Mixpanel, Unity Ads, ...)
        │
        ▼
Persistence & Compliance Attestation
```

## Status

This is an early-stage reference implementation accompanying a filed patent application. The adapter set currently includes an example Firebase adapter; community contributions for additional SDK adapters (Meta Audience Network, AppsFlyer, Mixpanel, Unity Ads, etc.) are welcome.

**Roadmap:**
- [ ] Meta Audience Network adapter
- [ ] AppsFlyer adapter
- [ ] Mixpanel adapter
- [ ] Unity Ads adapter
- [ ] Android (Kotlin) reference implementation
- [ ] Per-intent OS privacy declaration schema alignment subsystem
- [ ] Behavioral verification (network proxy observation)

## Patent Status

This project's core architecture — atomic SDK consent dispatch, receipt-chained audit ledger, capability negotiation protocol, and compliance attestation engine — is described in a filed U.S. provisional patent application (Application No. 64/087,949, filed June 11, 2026). The code in this repository is provided under the MIT license below; the patent covers the underlying method and system.

## Contributing

Adapters should implement the `ConsentAdapter` protocol in `Sources/ConsentBus/Adapters/ConsentAdapter.swift`. See `FirebaseConsentAdapterExample.swift` for the expected pattern. PRs welcome.

## License

MIT — see [LICENSE](LICENSE).
