# Changelog

All notable changes to ConsentBus are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [Semantic Versioning](https://semver.org/) (pre-1.0, so minor bumps may include breaking changes).

## [Unreleased]

### Added
- Real Ed25519 digital signing for `ComplianceAttestationReport` — asymmetric, not HMAC, so a regulator can verify a report with only `ConsentBus.shared.compliancePublicKey`, never a device secret. `ComplianceAttestationEngine.verify(_:publicKey:)` performs independent verification.
- Persistent audit ledger: HMAC key stored in the Keychain, committed entries stored on disk, so the audit trail survives app relaunch instead of living only in memory.
- Late-registering adapters are automatically synced (`sourceSignal: .adapterSync`) to every already-established per-purpose consent decision before `register(adapter:)` returns.
- `ConsentBus.shared.isPersistenceDegraded` — publicly observable flag so a host app can detect a Keychain/disk fallback instead of it being silent.
- Per-adapter dispatch timeout (10s) so one hung adapter can't block dispatch — or, since `ConsentBus` is a global-actor singleton every consent operation funnels through, the entire app — indefinitely.
- `AdapterReceipt.attemptCount` — records how many times an adapter's `apply(_:)` was actually called before the final receipt, so retry history is compliance-visible.
- `ConsentBusError.duplicateAdapter` — registering two adapters with the same `sdkIdentifier` now throws instead of silently double-dispatching every future consent change.
- CI: a genuine iOS Simulator test job, a latest-stable-Xcode job, and a Swift Package Index manifest-validation job, alongside the existing Xcode-15.4-minimum job.
- `SECURITY.md`, and a patent/CLA disclosure section in `CONTRIBUTING.md`.
- Meta Audience Network, AppsFlyer, Mixpanel, and Unity Ads adapters (stubs — see the adapter table in the README).
- `ConsentBusDemo` executable target (`swift run ConsentBusDemo`).

### Changed
- **Relicensed from MIT to Apache License 2.0.** The prior MIT license explicitly stated it granted no patent rights, which is a stronger blocker to org adoption than plain silence given the pending patent application; Apache 2.0's Section 3 grants an explicit patent license scoped to using/modifying/distributing this codebase.
- Adapter dispatch within a single `setConsent` call is now concurrent instead of sequential, so all adapters receive a given consent change as close to simultaneously as possible.
- Exponential backoff now includes jitter (equal jitter: half the computed delay fixed, up to half random) to avoid synchronized retry storms.
- `ConsentFSM` allows idempotent self-transitions (e.g. `.granted → .granted`) instead of throwing — real callers need to re-assert an already-current state (e.g. re-broadcasting on launch).
- `ConsentEvent.version` is now a race-free, actor-local monotonic counter instead of a speculative read of the ledger's version count taken before the (potentially multi-second) dispatch phase — the earlier approach could let two concurrent `setConsent` calls stamp events with a version that didn't match the `LedgerEntry` they ended up recorded in.

### Fixed
- **Critical**: `ConsentBus.shared` crashed the entire host app (via `assertionFailure`, which is fatal in debug/test builds) whenever persistent Keychain access failed, instead of degrading gracefully to in-memory as documented. Found by testing on a real iOS Simulator rather than assuming macOS behavior transfers — confirmed via `OSStatus -34018` (`errSecMissingEntitlement`).
- `AuditLedger.verifyChainIntegrity()` now recomputes each entry's HMAC from its actual stored content, not just the previous/current hash linkage — the earlier version couldn't detect tampering with a receipt's fields as long as the stored hash strings were left untouched.
- Fixed `JSONEncoder` key-ordering non-determinism (via `.sortedKeys`) that could otherwise make the same content hash differently between commit time and a later integrity check, causing spurious tamper-detection failures on completely unmodified data.
- The retry mechanism no longer retries `NOT_SUPPORTED` receipts — only genuine `FAILED` ones. Retrying a structural capability mismatch could never succeed and was adding multi-second delays for no reason.
- Fixed a single global `ConsentFSM` being shared across all consent purposes, which made it impossible to independently revoke/grant two different purposes in sequence — the FSM is now scoped per purpose.

## [0.2.0] - 2026-08-18

### Added
- 9 new tests (FSM invalid-transition and tamper-detection cases, retry-mechanism coverage, coverage-score edge cases, NOT_SUPPORTED distinction).
- `CONTRIBUTING.md`, GitHub issue templates.

### Fixed
- `import Crypto` → `import CryptoKit` (the package had no dependency on swift-crypto; `CryptoKit` is the correct system-framework equivalent for Apple platforms).

## [0.1.0] - 2026-07-07

Initial complete implementation: `ConsentBus` actor broker, per-purpose `ConsentFSM`, `AuditLedger` with an HMAC-SHA256 hash chain, `ComplianceAttestationEngine` with `ComplianceCoverageScore`, and the `FirebaseConsentAdapterExample` reference adapter.
