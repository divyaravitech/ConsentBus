# ``ConsentBus``

Coordinated, tamper-evident consent propagation across heterogeneous mobile SDKs.

## Overview

Modern apps embed 5–20+ third-party SDKs — analytics, advertising, attribution. When a user changes their privacy consent, there's no standard way to propagate that change to all of them simultaneously and verifiably, and no way to distinguish "this SDK doesn't support that consent category" from "this SDK failed to honor the restriction."

``ConsentBus`` sits between your app's consent UI and your third-party SDKs, and provides:

- **Serialized, coordinated dispatch** — consent operations run one at a time; each change is delivered to every registered adapter in one pass (concurrently within the pass, each adapter with its own timeout). This narrows, but cannot eliminate, the window in which SDKs disagree.
- **Structured receipts** — every adapter returns an ``AdapterReceipt`` with the exact native API call it made, and a three-way outcome (``PropagationStatus/applied``, ``PropagationStatus/failed``, or ``PropagationStatus/notSupported``) that keeps capability gaps from being penalized as compliance failures.
- **A persisted, tamper-evident audit ledger** — every consent change is committed to an ``AuditLedger`` entry whose HMAC-SHA256 hash chains to the one before it, with the key in the Keychain and entries on disk so the record survives app relaunch.
- **Signed compliance reports** — ``ComplianceAttestationReport`` carries an Ed25519 signature a DPO or regulator can verify independently, with only ``ConsentBus/compliancePublicKey`` — never a device secret.

## Getting started

```swift
import ConsentBus

// Register adapters at app launch. A late-registering adapter (e.g. a
// lazily-initialized SDK) is automatically synced to whatever consent
// state was already established.
try await ConsentBus.shared.register(adapter: FirebaseConsentAdapterExample())

// Propagate a consent change to every registered adapter in one coordinated pass
let entry = try await ConsentBus.shared.setConsent(.revoked, purpose: .adPersonalization, source: .userUI)

// Export a signed compliance report
let report = await ConsentBus.shared.exportComplianceReport()

// Check the audit chain's integrity (requires the ledger's HMAC key — see THREAT_MODEL.md)
let isValid = await ConsentBus.shared.verifyAuditChainIntegrity()
```

See the [README](https://github.com/divyaravitech/ConsentBus) for the full adapter table, a compliance report example, and how to wire up a new SDK adapter.

## Topics

### Essentials

- ``ConsentBus``
- ``ConsentState``
- ``ConsentPurpose``
- ``ConsentSource``

### Adapters

- ``ConsentAdapter``
- ``ConsentCapabilitySchema``
- ``AdapterReceipt``
- ``PropagationStatus``

### Audit and compliance

- ``AuditLedger``
- ``AuditLedgerPersistence``
- ``LedgerEntry``
- ``ComplianceAttestationEngine``
- ``ComplianceAttestationReport``
- ``PropagationStatusEntry``

### Errors

- ``ConsentError``
- ``ConsentBusError``
