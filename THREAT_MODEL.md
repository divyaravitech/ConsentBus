# Threat model and limits

This document says precisely what ConsentBus guarantees, under which assumptions, and what it does **not** do. It describes the current pre-1.0 behavior. If you intend to rely on a ConsentBus report as compliance evidence, read the "does not guarantee" section first.

## What ConsentBus is for

When a user changes a consent decision, ConsentBus delivers that change to every registered third-party SDK adapter in a defined order and keeps a tamper-evident record of what each adapter reported. It is plumbing between your consent UI and your SDKs.

It is **not** a consent-management platform (it renders no consent UI and does not check that an incoming consent signal is legally valid), and it is not legal advice or a compliance guarantee.

## Trust assumptions

- The host app, and the adapters its developers write, run correctly. ConsentBus cannot defend against the app that embeds it.
- Third-party SDKs are **not** trusted to honor anything. ConsentBus can only call each SDK's public consent API.
- An auditor is a separate party who sees only exported artifacts.

## What ConsentBus guarantees (under those assumptions)

1. **Ordering.** Consent operations (`setConsent`, and the state replay `register(adapter:)` performs) are mutually exclusive and run in arrival order. One operation's dispatch never overlaps another's, and each sees the effects of every earlier one. Covered by `ConsentOperationSerializationTests`.
2. **Every outcome is recorded.** Each adapter yields a receipt — applied, failed, or not supported — including timeouts and the number of attempts made.
3. **Decisions survive relaunch** — provided persistence is healthy (`ConsentBus.shared.isPersistenceDegraded == false`). Per-purpose state is rebuilt from the ledger at startup and re-applied to each adapter as it registers. Covered by `RelaunchRestoreTests`.
4. **Edits to a committed ledger entry are detected** by `verifyAuditChainIntegrity()`, run by the holder of the ledger's HMAC key.
5. **A signed report altered after export fails verification** (`ComplianceAttestationEngine.verify`).

## What ConsentBus does not guarantee

1. **That an SDK actually honored the change.** A receipt is the adapter's own report, and for most vendor APIs "applied" means only "the call returned without error" — many consent APIs offer no way to read the state back. ConsentBus does not observe what the SDK subsequently does.
2. **That a timed-out or failed call had no effect.** After a timeout the call may still complete later, so a `failed` receipt can really mean "unknown". Retries invoke `apply` again, so adapters must be idempotent.
3. **That the window is closed.** Dispatch is coordinated, not atomic or all-or-nothing: some adapters can succeed while others fail. An SDK that initializes or collects before it is registered, or that is on by default until registration, is outside ConsentBus's control — initialize SDKs after registering them.
4. **Tamper-evidence against someone with the key or the device.**
   - The HMAC key sits in the device Keychain next to the ledger, so a party with that access can rewrite the whole chain.
   - The chain head is not anchored anywhere external: truncating the newest entries, or restoring an older copy of the ledger, passes verification.
   - A third party without the key cannot recompute the chain. A report's `chainProof` is a list of HMAC outputs covered by the report's signature; it is not independently recomputable.
5. **Where the signing key came from.** The Ed25519 signing key is a software key stored on the device, not hardware-bound, and reports carry no attestation that the key belongs to a genuine app instance. A valid signature shows the report was not modified after signing by that key's holder — not who the holder is. Key rotation and revocation are not implemented.
6. **A full history report.** A report describes the most recent consent change, plus the hash of every ledger entry.
7. **Latency isolation.** Because operations are serialized, one slow adapter delays everything queued behind it, by up to (retries + 1) × the 10-second adapter timeout plus backoff.
8. **Durability when storage fails.** If the Keychain or disk is unavailable, ConsentBus falls back to in-memory operation: the audit trail and consent restoration do not survive a relaunch. It never crashes over this; check `isPersistenceDegraded`.
9. **Scalability of the ledger.** Re-syncing at launch adds an entry per (adapter, purpose), and the file store rewrites the whole file on each commit. Fine for a reference implementation; not designed for very long-lived, high-volume use.
10. **Negotiated capabilities.** Capability schemas are static declarations written by the integrator; nothing is negotiated with the SDK. The `rollback` status exists but is reserved and never produced.

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md).
