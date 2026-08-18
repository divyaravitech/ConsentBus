# Security Policy

ConsentBus handles consent state, an HMAC signing key, and an Ed25519 signing key used to authenticate compliance reports. Vulnerabilities here have real privacy/compliance consequences — please report responsibly rather than filing a public issue.

## Reporting a vulnerability

Email **divya.ravi@unity3d.com** with:
- A description of the issue and its potential impact
- Steps to reproduce (a minimal Swift snippet is ideal)
- The ConsentBus version or commit SHA affected

Please do not open a public GitHub issue for suspected security vulnerabilities until a fix has been released.

## What's in scope

- Anything that could allow the tamper-evident audit ledger (`AuditLedger`) to be silently corrupted without `verifyChainIntegrity()` detecting it
- Anything that could allow a `ComplianceAttestationReport` to pass `ComplianceAttestationEngine.verify(_:publicKey:)` despite being forged or altered
- Keychain key handling issues (e.g. the HMAC key or Ed25519 signing key becoming recoverable or predictable)
- Consent state that fails to propagate to a registered adapter without that failure being reflected in the resulting `AdapterReceipt`

## What's out of scope

- The four stub adapters (Meta, AppsFlyer, Mixpanel, Unity Ads) not calling a real vendor SDK — that's a known, intentional placeholder, not a vulnerability. See [CONTRIBUTING.md](CONTRIBUTING.md).
- Issues in a vendor SDK's own consent API, once a real (non-stub) adapter calls it

## Response

We'll acknowledge reports within 5 business days and aim to ship a fix or mitigation before any public disclosure.
