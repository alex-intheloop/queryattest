# Governance

QueryAttest is currently an early-stage, maintainer-led open-source project. This document defines how technical decisions are made while the project is in alpha.

## Principles

1. Security and evidence claims must remain narrower than what automated tests and documented assumptions support.
2. PostgreSQL least privilege and row-level security are final boundaries; application-layer policy is defense in depth.
3. Compatibility may change before `1.0`, but breaking changes must be documented in the changelog.
4. Security-sensitive changes require explicit threat-model and regression-test review.
5. Decisions should be recorded in issues, pull requests, or architecture documents rather than private chat.

## Decision process

Small, reversible changes may be accepted through normal pull-request review. Changes to public schemas, ticket formats, cryptographic construction, identity, authorization, database execution, persisted state, or evidence semantics require a design issue before implementation.

A proposal is accepted when the maintainers responsible for the affected area agree that:

- the threat model and non-goals are explicit;
- success, failure, and adversarial cases are tested;
- migration or compatibility effects are documented;
- public claims remain accurate;
- the change can be maintained with the project's available capacity.

When consensus is not possible, the repository owner makes the final decision and records the rationale publicly.

## Maintainer responsibilities

Maintainers are expected to review contributions, triage security reports, protect release credentials, keep CI and dependency policies healthy, document breaking changes, and disclose conflicts of interest that affect a decision.

Contributor access should increase gradually: contributor, regular contributor, reviewer, area maintainer, then core maintainer. Promotion is based on sustained technical judgment, respectful review behavior, and demonstrated care for trust-boundary invariants—not commit count alone.

## Security-sensitive areas

The following areas require heightened review:

- ticket signing, verification, key derivation, and identity binding;
- semantic compilation and SQL policy validation;
- tenant context, PostgreSQL execution, RLS assumptions, and timeouts;
- state transitions, encryption, audit evidence, and redaction;
- release workflows, dependency changes, and supply-chain configuration.

See [SECURITY.md](SECURITY.md) for private vulnerability reporting.
