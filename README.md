# Lursystem

**A self-hosted whistleblower-reporting and case-handling system for
Swedish employers.** Built on
[`rustio-admin`](https://github.com/abdulwahed-sweden/rustio-admin).

Designed for compliance with the EU Whistleblower Directive
(2019/1937), transposed into Swedish law as
**lag (2021:890) om skydd för personer som rapporterar om
missförhållanden**. Every Swedish employer with 50+ staff must
have an internal reporting channel. Lursystem is that channel —
self-hosted, audit-grade, no third party touches the data.

> **Status: scaffolding.** The framework substrate (rustio-admin
> 0.7) is published. The domain code lands across the build
> roadmap below. This README is a contract for what gets built,
> not a description of what exists yet.

---

## Why self-hosted

The Swedish whistleblower SaaS market (Whistlelink, Walor, Etika,
EQS, etc.) routes reports through a third party's infrastructure
in a different EU country. That's defensible for many buyers —
and unacceptable for some.

Lursystem is for the second category: compliance leads,
public-sector procurement offices, and SMEs that have decided
the data stays on their own server, in their own country, behind
their own audit chain. The system is a single deploy: one binary,
one Postgres, one stylesheet, no build step.

It's not a SaaS competitor. It's the option for buyers who don't
want a SaaS.

## What's in scope

The framework (rustio-admin 0.7) ships the security substrate:

- TOTP MFA + single-use Argon2id-hashed backup codes.
- Re-auth wall on every destructive admin action.
- Per-request `correlation_id` chain across the audit trail.
- Centralised session invalidation (Doctrine 22).
- Per-model permissions + 5-tier role hierarchy.
- Account lockout + auto-throttle on failed logins.
- Admin-driven recovery (R2) and self-service password recovery
  (R1).

Lursystem adds, on top of that substrate:

| Schema | Purpose |
|---|---|
| `Report` | The submission. Anonymous-capable. Body, severity, channel, attachments |
| `Case` | Handler-assigned wrapper around a report. Status lifecycle: intake → triage → investigating → resolved → archived |
| `CaseAction` | Every state change, internal note, document download, status flip — the case-level audit overlay |
| `Document` | Attachments with size cap, retention timestamps, virus-scan hook |
| `Disclosure` | Every request to read reporter-identifying data. Requires re-auth. Irreversible once consumed |

## Roles

Four roles, mapped onto the rustio-admin role hierarchy:

- **Reporter** — limited self-service. Can submit a report and
  view the status of their own report. No admin access.
- **Handler** — assigned to specific cases. Can read the body, add
  internal notes, change status. Re-auth gated for sensitive
  actions.
- **Compliance lead** — sees all cases, can reassign, can request
  reporter-identity disclosure (re-auth + audit row + irreversible).
  Can export case packages.
- **Auditor** — read-only access to the audit log. Sees case
  metadata, but not bodies. Verifies the forensic chain without
  needing case-content access.

## Flows

**Anonymous submission.** A public page outside `/admin` accepts a
report with no auth. The framework's CSRF + correlation_id
middleware still apply. The report lands in `intake` state.

**Handler workflow.** Sign in → MFA challenge → assigned case
list. Open case → read body + history. Add internal notes, flip
status, attach documents. Every action audited under the case's
correlation chain.

**Reporter-identity unmask.** Compliance leads can request an
unmask when investigation requires it. Re-auth with both factors.
A `Disclosure` row is written. The audit chain ties the disclosure
to the lead, the time, the case, and the reason. Irreversible.

**Quarterly compliance export.** Auditors can package every case +
every audit row + every disclosure into a signed, timestamped
archive for regulatory review.

## Build roadmap

Four to six weeks of focused work. The framework does ~70% of the
work; this project is the domain logic plus the public submission
page.

| Phase | Concern | Output |
|---|---|---|
| 1 | Schema + role-tier wiring | 6 models, migrations, RBAC matrix |
| 2 | Anonymous public submission page | `/report/new` route outside `/admin` |
| 3 | Handler case workflow | List, detail, status transitions, internal notes |
| 4 | Reporter-identity unmask | Re-auth + Disclosure row + audit chain |
| 5 | Auditor read-only surface | Audit-log view with `correlation_id` pivot |
| 6 | Quarterly export | Signed package generation |

Each phase ships as a coherent commit set. The framework's gate
discipline (`cargo fmt + cargo test --workspace + cargo clippy
-- -D warnings`) carries through.

## What this project does NOT do

- Customer-facing apps beyond the public submission page.
- Reporting / analytics / dashboards.
- Multi-tenancy. One deploy per client; one Postgres per deploy.
- Mobile apps.
- Real-time push / WebSockets / SSE.
- Integration with HRIS, ticketing, or external case-management
  tools (out of scope for the reference; possible per-client
  custom work).

These are deliberate exclusions. The product is a small, focused,
auditable channel — not a platform.

## Why "Lursystem"

Short. Memorable. Swedish-rooted. Means a system for receiving
tips. Avoids the marketing-heavy "visselblåsare" naming.

## Tech

- Rust (stable, MSRV pinned by rustio-admin)
- [`rustio-admin`](https://crates.io/crates/rustio-admin) 0.7
- PostgreSQL 14+
- Single binary, no build step, one stylesheet

## License

MIT. See [`LICENSE`](./LICENSE).

## Status

| | |
|---|---|
| Framework substrate | `rustio-admin@0.7.0` (published 2026-05-11) |
| Project | Scaffolding phase — schemas land next |
| Branch | `main` |

The framework's design contracts (`DESIGN_RECOVERY.md`,
`DESIGN_SESSIONS.md`, `DESIGN_AUDIT.md`,
`DESIGN_R2_ORGANISATIONAL.md`, `DESIGN_R3_MFA.md`) govern the
security-sensitive behaviour. Project-level decisions live in
this repository.
