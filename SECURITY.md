# Security policy

QueryAttest is an **alpha reference implementation** for evidence-backed PostgreSQL analytics. It has not received an independent security audit and must not be treated as the sole authorization boundary for sensitive production data.

## Supported versions

Security fixes are applied to the newest `0.1.x` release only. Older alpha releases may contain incompatible state, ticket, or evidence formats.

| Version | Supported |
|---|---|
| Latest `0.1.x` | Yes |
| Older releases | No |

## Reporting a vulnerability

Please use GitHub's private security-advisory flow for the repository rather than opening a public issue. Include:

- affected version and commit;
- threat scenario and required attacker capabilities;
- minimal reproduction or adversarial test;
- expected invariant and observed behavior;
- whether tenant isolation, authorization, ticket integrity, audit evidence, or availability is affected.

Do not include real credentials, customer data, or production connection strings.

A public issue is appropriate for hardening ideas that do not disclose an exploitable weakness. Suspected tenant-boundary bypasses, ticket forgery/replay, SQL-policy bypasses, secret exposure, or audit-integrity failures should remain private until a fix is available.

## Security boundaries

The package is defense in depth, not a replacement for PostgreSQL controls. A deployment is expected to retain:

- a non-superuser database role without `BYPASSRLS`;
- forced row-level security on every tenant-bearing table;
- read-only transactions and restrictive grants;
- protected semantic catalog, policy, identity provider, root secret, and state store;
- private database networking, TLS verification, rate limits, and external audit retention for remote deployments.

The built-in environment principal provider is for local `stdio` or disposable demonstrations. It is not remote-user authentication. Non-loopback Streamable HTTP is refused by default.

See [docs/threat-model.md](docs/threat-model.md) for assumptions, residual risks, and non-goals.
