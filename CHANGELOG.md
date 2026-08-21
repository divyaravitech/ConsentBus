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
- `ConsentBusDemo` executable target (`swift run ConsentBusDemo`), including a signature-verification step that tampers with the exported JSON and shows verification correctly rejecting it.
- `ComplianceAttestationReport.consentChangedAt` — when the underlying consent change actually happened, distinct from `generatedAt` (when the report was exported, which can be considerably later).
- Public initializers for `LedgerEntry`, `ComplianceAttestationReport`, and `PropagationStatusEntry` — previously only constructible via `Codable` decoding or from inside the module, blocking third-party consumers (and the demo) from constructing synthetic values for their own tests.

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
- **Critical**: the per-adapter dispatch timeout didn't actually work against the failure mode it exists to protect against. It used `withTaskGroup`, whose implicit scope-exit drain waits for *all* child tasks to actually finish — not just be cancelled — before returning; a truly blocking call (e.g. a real vendor SDK's synchronous network request, which won't check `Task.isCancelled`) meant the "timeout" still blocked for the full duration of the hang. Verified empirically with a standalone diagnostic (5s blocking call vs. a 1s timeout took 5s, not 1s) before and after the fix. Rewritten using an unstructured `Task` raced via `withCheckedContinuation`, which can genuinely abandon the loser without waiting for it — verified the same diagnostic now returns in ~1s. The adapter-timeout test was also strengthened: it used `Task.sleep` (cancellation-aware), which would have passed against the broken implementation too, giving false confidence; it now uses a true thread-blocking call.
- Fixed a TOCTOU race in `register(adapter:)`'s duplicate-`sdkIdentifier` guard: the check awaited each existing adapter's `sdkIdentifier`, a genuine suspension point a concurrent `register()` call could interleave across, defeating the guard entirely for adapters registered at nearly the same time. Fixed with a synchronously-maintained `Set<String>` checked and inserted with no intervening `await`. Verified with a 20-way concurrent registration stress test.
- `ComplianceAttestationEngine.generateReport()` no longer silently ships a report with a blank/broken signature if signing itself fails — it returns `nil`, matching the existing "nothing to report" contract, rather than a report that merely looks trustworthy.
- Keychain items now use `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` instead of the non-`ThisDeviceOnly` variant — the ledger's entries live only on local disk and are never iCloud-synced, so letting the key sync to another device was a semantic mismatch (a synced key with no corresponding synced data).

## [0.2.0] - 2026-08-18

### Added
- 9 new tests (FSM invalid-transition and tamper-detection cases, retry-mechanism coverage, coverage-score edge cases, NOT_SUPPORTED distinction).
- `CONTRIBUTING.md`, GitHub issue templates.

### Fixed
- `import Crypto` → `import CryptoKit` (the package had no dependency on swift-crypto; `CryptoKit` is the correct system-framework equivalent for Apple platforms).

## [0.1.0] - 2026-07-07

Initial complete implementation: `ConsentBus` actor broker, per-purpose `ConsentFSM`, `AuditLedger` with an HMAC-SHA256 hash chain, `ComplianceAttestationEngine` with `ComplianceCoverageScore`, and the `FirebaseConsentAdapterExample` reference adapter.
