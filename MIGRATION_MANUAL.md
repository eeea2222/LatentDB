# LatentDB First-Run Migration — User Manual

> A complete guide to the **first-run migration** feature: how a brand-new tenant
> keeps running its existing ("old") system, evaluates a target ("selected")
> system, and receives a precise, **non-destructive** report — including at logout
> — describing exactly how its data would move.

---

## Table of contents

1. [What this is](#1-what-this-is)
2. [Core concepts](#2-core-concepts)
3. [The lifecycle (state machine)](#3-the-lifecycle-state-machine)
4. [Data-management guarantees](#4-data-management-guarantees)
5. [Quick start (5 minutes)](#5-quick-start-5-minutes)
6. [API reference](#6-api-reference)
7. [The migration report, field by field](#7-the-migration-report-field-by-field)
8. [Conflict catalog](#8-conflict-catalog)
9. [The logout hand-off](#9-the-logout-hand-off)
10. [Worked example](#10-worked-example)
11. [Permissions & auditing](#11-permissions--auditing)
12. [Troubleshooting](#12-troubleshooting)
13. [FAQ](#13-faq)
14. [Glossary](#14-glossary)

---

## 1. What this is

When a new organization signs into LatentDB for the first time, it usually
**already runs some business model** — a set of object types (accounts, invoices,
widgets, …) with records inside them. LatentDB calls that the **old system**.

The first-run migration feature lets that tenant:

- **Boot the old system** and keep working in it — nothing is taken away.
- **Select a target system** — one of the built-in Builder templates (Finance,
  Procurement, Inventory, CRM, HR) — to evaluate moving onto.
- **See a precise plan** of how every object, field, and record would map from
  the old system onto the selected one, with every conflict called out.
- **Receive that plan as output on logout**, rendered for whichever system they
  were booted into.

Crucially, this entire feature is **read-only with respect to your data**. It
plans and reports; it never moves, rewrites, archives, or deletes a record. You
decide if and when to actually adopt the new system (via the Builder template
install path), with the report in hand.

---

## 2. Core concepts

| Concept | Meaning |
|---|---|
| **Old system** (`SystemKind::old`) | The object types currently installed in your tenant, plus their records. Captured live as a `SystemSnapshot`. |
| **Selected system** (`SystemKind::selected`) | A built-in Builder template you are evaluating. Identified by a template **key**: `finance`, `procurement`, `inventory`, `crm`, `hr`. |
| **Active system** | Which of the two you are currently "booted" into. Determines what logout reports on. Defaults to **old**. |
| **Migration session** | One per tenant. Persists the captured old-system snapshot, the selected target (if any), the active system, the status, and the last report. |
| **Plan** | The computed old → selected mapping: object-by-object, field-by-field, with record counts and conflicts. |
| **Report** | A self-contained, non-destructive artifact for one system. For *old* it is an inventory; for *selected* it embeds the plan. |

### Selectable target systems

The selectable target keys are exactly the built-in Builder templates. You can
list them at any time:

```bash
curl -s $BASE/v1/builder/templates -H "Authorization: Bearer $TOKEN"
# -> [{ "key": "finance", ... }, { "key": "procurement", ... }, ...]
```

---

## 3. The lifecycle (state machine)

A session has a `status` that advances as you go. It never silently regresses.

```
                 start_migration(no target)
   (no session) ───────────────────────────►  booted_old
                 start_migration(target=…)            │
   (no session) ───────────────────────────►  target_selected
                                                       │
        select_target_system(key) ─────────────────────┤
        set_active_system(selected) ────────────────────┤  (from booted_old)
                                                       │
        migration_report(...) / logout ───────────────►  reported
```

| `status` | Meaning |
|---|---|
| `booted_old` | Running the old system; no target chosen yet. |
| `target_selected` | A target template has been selected (old system still fully intact). |
| `reported` | At least one report has been emitted (e.g. at logout). |

`active_system` is tracked **separately** from `status`:

- `set_active_system("old")` — keep booting the old system (the default).
- `set_active_system("selected")` — switch the "active" pointer onto the selected
  system so logout reports on it. **Requires** that a target is already selected.
  This only re-points the session; it does **not** migrate data.

---

## 4. Data-management guarantees

These hold for every operation in this feature:

1. **Non-destructive.** No record is created, updated, archived, or deleted.
   Selecting, planning, activating, and reporting are all read-only over your data.
2. **A plan is a plan.** The report explicitly states that nothing was moved. To
   actually adopt the selected system you install its template — a separate,
   deliberate action you take with the report in hand.
3. **Live, accurate counts.** Record counts in snapshots, plans, and reports are
   computed at the moment of the call with a single grouped query over *active*
   (non-archived) records — not stale values cached at session start.
4. **Tenant-scoped.** Every query is scoped to your tenant; the feature cannot see
   or report on another tenant's data.
5. **Audited.** Every mutating step writes an audit row, and report generation
   also emits a domain event. See [§11](#11-permissions--auditing).
6. **One session per tenant.** Starting again refreshes the snapshot in place; it
   does not fork history.
7. **Conflicts are surfaced, not hidden.** Type mismatches, dropped fields,
   unmapped objects, and missing required target fields are all enumerated so a
   human can decide before any real import.

---

## 5. Quick start (5 minutes)

Assume `$BASE` is your API origin and you've logged in as a tenant admin:

```bash
BASE=http://localhost:8080
TOKEN=$(curl -s $BASE/v1/auth/login -H 'content-type: application/json' \
  -d '{"tenant":"acme","email":"admin@acme.test","password":"…"}' | jq -r .token)
AUTH="Authorization: Bearer $TOKEN"
```

```bash
# 1. Start onboarding — snapshots your old system, boots it.
curl -s $BASE/v1/migration/start -X POST -H "$AUTH" \
  -H 'content-type: application/json' -d '{}'

# 2. Pick a target system to evaluate.
curl -s $BASE/v1/migration/select -X POST -H "$AUTH" \
  -H 'content-type: application/json' -d '{"key":"finance"}'

# 3. See the full old -> selected mapping.
curl -s $BASE/v1/migration/plan -H "$AUTH" | jq .summary

# 4. (Optional) Switch the active system so logout reports on the new one.
curl -s $BASE/v1/migration/active -X POST -H "$AUTH" \
  -H 'content-type: application/json' -d '{"system":"selected"}'

# 5. Log out — the response carries the report for your active system.
curl -s $BASE/v1/auth/logout -X POST -H "$AUTH" | jq .migration_report.summary
```

---

## 6. API reference

All endpoints require a `Bearer` token. Mutating endpoints require tenant-admin
rights (`configure` on the `migration` resource); reads require `read` on it.

### `POST /v1/migration/start`

Begin (or re-capture) the session. Snapshots the old system and boots it.

**Body** (all optional):

```json
{ "target_system": "finance" }
```

**Returns** a `MigrationSession`. Idempotent — re-running refreshes the snapshot.

### `GET /v1/migration`

Returns the current `MigrationSession`, or `null` if onboarding was never started.

### `POST /v1/migration/select`

Choose or change the selected target system.

**Body:** `{ "key": "finance" }` — must be a known template key.
**Returns** the updated `MigrationSession` (`status: "target_selected"`).
**Errors:** `404 not_found` if the key is unknown; `412 failed_precondition` if no
session has been started.

### `POST /v1/migration/active`

Re-point the active system. **Non-destructive.**

**Body:** `{ "system": "old" }` or `{ "system": "selected" }`.
**Returns** the updated `MigrationSession`.
**Errors:** `412 failed_precondition` if you activate `selected` without first
selecting a target.

### `GET /v1/migration/plan`

Compute the live old → selected mapping.

**Returns** a `MigrationPlan`.
**Errors:** `412 failed_precondition` if no target is selected.

### `GET /v1/migration/report`

Generate **and persist** a report.

**Query:** `?system=old` or `?system=selected`. Omitted ⇒ the session's active
system.
**Returns** a `MigrationReport`. Advances `status` to `reported`.

### `POST /v1/auth/logout`

Revokes the session token. If the tenant has a first-run migration session, the
response includes the report for the active system:

```json
{ "ok": true, "migration_report": { "...": "MigrationReport" } }
```

If there is no migration session, `migration_report` is omitted. Report generation
never blocks logout.

---

## 7. The migration report, field by field

`MigrationReport`:

| Field | Type | Notes |
|---|---|---|
| `id` | string | Unique id for this report. |
| `tenant_id` | string | The tenant it describes. |
| `generated_at` | RFC3339 string | When it was produced. |
| `for_system` | `"old"` \| `"selected"` | Which system this report is about. |
| `source_system` | `SystemSnapshot` | The old system inventory (always present). |
| `target_system` | `SystemSnapshot`? | The selected system (present only for a `selected` report). |
| `plan` | `MigrationPlan`? | Present only for a `selected` report. |
| `summary` | `MigrationSummary` | Roll-up numbers (see below). |
| `notes` | string[] | Plain-language guidance, including the explicit "nothing was moved" assurance. |

`MigrationSummary`:

| Field | Meaning |
|---|---|
| `source_objects` | Number of object types in the old system. |
| `target_objects` | Number of object types in the selected system (0 for an old-only report). |
| `mapped_objects` | Old objects that have a counterpart in the selected system. |
| `source_records` | Total active records in the old system. |
| `records_mappable` | Records in objects that have a target (would carry over). |
| `records_unmapped` | Records that have no target (stay in the old system). |
| `conflicts` | Total conflicts found. |

`SystemSnapshot`:

```json
{
  "kind": "old",
  "key": "installed",
  "label": "Your current (old) system",
  "objects": [
    { "key": "invoice", "label": "invoice", "module": "legacy",
      "field_keys": ["number", "amount", "status", "legacy_code"],
      "record_count": 3 }
  ]
}
```

`MigrationPlan`:

```json
{
  "source_system": { "...": "SystemSnapshot (old)" },
  "target_system": { "...": "SystemSnapshot (selected)" },
  "object_mappings": [ { "...": "ObjectMapping" } ],
  "conflicts": [ { "...": "MigrationConflict" } ],
  "summary": { "...": "MigrationSummary" }
}
```

`ObjectMapping` describes one object type's fate. `source_object`/`target_object`
are `null` when there is no source (new object) or no target (unmapped object).
Each `field_mappings` entry has a `status` from the table below.

`FieldMapping.status` values:

| Status | Meaning |
|---|---|
| `mapped` | Same key, same type — moves cleanly. |
| `type_mismatch` | Same key, different type — values need transformation. |
| `added_in_target` | New field in the selected system; records gain an empty field. |
| `dropped_from_source` | Old field with no target; its data would not carry over. |
| `missing_required_in_target` | Required target field with no source — needs a default. |

---

## 8. Conflict catalog

`MigrationConflict.kind` values and how to resolve them:

| Kind | What it means | Typical resolution |
|---|---|---|
| `type_mismatch` | A field exists in both systems with different types (e.g. `tier` is free text in the old system but an enum in the target). | Decide a transform / allowed value set before import. |
| `dropped_field` | An old field has no home in the target; its values would be lost. | Add an equivalent field to the target (via Builder) or accept the loss. |
| `missing_required_target` | The target requires a field the source can't populate. | Provide a default or backfill before import. |
| `unmapped_source_object` | A whole old object type has no counterpart; its records stay in the old system. | Keep it in the old system, or model it in the target first. |

A `selected` report with **zero conflicts** says so explicitly in `notes`: the
selected system is a clean fit.

---

## 9. The logout hand-off

The phrase "when they log out, provide output appropriate to either the old or the
selected system" maps to this behavior:

- On `POST /v1/auth/logout`, before the session token is revoked, the kernel
  resolves the tenant and — if a migration session exists — builds the report for
  the **active** system and returns it on the response under `migration_report`.
- If the active system is **old**, the report is an inventory of what you're
  running now (so you can keep booting it confidently).
- If the active system is **selected**, the report embeds the full migration plan.
- The session's `status` advances to `reported` and the report is stored on the
  session (also retrievable later via `GET /v1/migration` → `last_report`).

Report generation is best-effort: if anything goes wrong, logout still succeeds and
simply omits the report.

---

## 10. Worked example

Old system: `account` (with free-text `tier`), `invoice` (with an extra
`legacy_code` field), and `widget` (no finance counterpart) — 2 accounts, 3
invoices, 1 widget.

Select `finance` and fetch the plan summary:

```json
{
  "source_objects": 3,
  "target_objects": 4,
  "mapped_objects": 2,
  "source_records": 6,
  "records_mappable": 5,
  "records_unmapped": 1,
  "conflicts": 3
}
```

The three conflicts:

- `type_mismatch` on `account.tier` (text → enum),
- `dropped_field` on `invoice.legacy_code` (no target),
- `unmapped_source_object` on `widget` (1 record stays in the old system).

`account` and `invoice` map across (5 records); `widget`'s 1 record is retained in
the old system; `payment` and `budget` appear as **new** object types in the
target with no existing data.

---

## 11. Permissions & auditing

- **Who can use it:** mutating operations (`start`, `select`, `active`, `report`)
  require tenant-admin rights. Reads (`GET /v1/migration`, `plan`) require read on
  the `migration` resource. Ordinary members are denied (and the denial is audited).
- **Audit trail:** `migration.start`, `migration.select_target`,
  `migration.set_active_system`, and `migration.report` are written to the audit
  log, scoped to your tenant. Query them via `GET /v1/audit?action=migration.report`.
- **Events:** generating a report emits a `migration.report_generated` domain event
  for any downstream automation.

---

## 12. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `412 failed_precondition` on `select`/`plan`/`report` | No session started. | Call `POST /v1/migration/start` first. |
| `412 failed_precondition` on `plan` | No target selected. | `POST /v1/migration/select`. |
| `412 failed_precondition` on `active` (`selected`) | Activating selected with no target. | Select a target first. |
| `404 not_found` on `select`/`start` | Unknown template key. | Use a key from `GET /v1/builder/templates`. |
| `403 forbidden` | Not a tenant admin. | Use an admin account; members can't run onboarding. |
| Logout response has no `migration_report` | No session for the tenant. | Expected — start onboarding first. |
| Counts look low | They count only **active** records; archived rows are excluded. | Restore records, or treat archived as intentionally excluded. |

---

## 13. FAQ

**Does selecting a system change my data?** No. Nothing in this feature mutates
records. It plans and reports only.

**Can I keep using my old system indefinitely?** Yes. The default active system is
`old`, and you can stay there as long as you like.

**How do I actually adopt the selected system?** Install its Builder template
(`POST /v1/builder/templates/install`) once the plan looks right. That is a
separate, deliberate step — the migration feature gives you the plan to make that
decision.

**Can I switch targets?** Yes — call `select` again with a different key. The plan
and reports always reflect the currently selected target.

**Where's my last report?** On the session: `GET /v1/migration` → `last_report`.

**Is many-to-many / relation migration handled?** The plan maps object types and
fields. Relationship re-wiring is out of scope for the plan and should be handled
during the actual template install / data import.

---

## 14. Glossary

- **Tenant** — an isolated customer organization. All data and sessions are scoped
  to it.
- **Object type** — a metadata-defined business model (e.g. `invoice`). LatentDB
  has no hardcoded business tables; everything is an object type.
- **Builder template** — a packaged set of object types (and workflows) you can
  install. The selectable target systems are exactly these templates.
- **Snapshot** — a point-in-time inventory of a system's objects and record counts.
- **Active system** — the system a first-time user is currently booted into;
  determines what logout reports on.
