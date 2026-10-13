---
name: Bug report
about: Report a bug in ConsentBus
title: ''
labels: bug
assignees: ''
---

## Describe the bug

A clear, concise description of what's wrong.

## To reproduce

Steps to reproduce the behavior, ideally as a minimal Swift snippet:

```swift
// e.g.
try await ConsentBus.shared.setConsent(.revoked, purpose: .adPersonalization, source: .userUI)
```

## Expected behavior

What you expected to happen.

## Actual behavior

What actually happened. Include the exact error message, stack trace, or incorrect output if applicable.

## Environment

- ConsentBus version / commit:
- Swift version (`swift --version`):
- Platform (iOS version / macOS version):
- Xcode version (if applicable):

## Additional context

Anything else relevant — e.g. which adapters were registered, whether this involves the audit ledger, compliance report generation, or FSM transitions.
