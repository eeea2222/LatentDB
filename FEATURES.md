# LatentDB Features

LatentDB is a governed dynamic enterprise data plane. Tenants can define their own business model, but all access still flows through the kernel for tenant isolation, schema validation, RBAC, workflow, audit, AI visibility, and approval-gated actions.

## Platform Core

- Multi-tenant kernel with tenant-scoped service methods.
- SQLite-backed storage with in-memory and file modes.
- API health and readiness checks.
- Shared contracts for auth, errors, fields, object types, records, permissions, workflows, audit, pagination, feature flags, and Builder definitions.
- Feature flags for AI agents, semantic search, acceleration, cloud control plane, advanced permissions, usage metering, and agent action execution.
- No business module, UI surface, or AI path is expected to bypass kernel services.

## Governed Builder

- Builder UI for tenant admins to create and publish dynamic business objects without code.
- Draft lifecycle: `Draft`, `Validated`, and `Published`.
- Live JSON preview of the governed object definition.
- Builder draft persistence through tenant-scoped API/kernel services.
- Validation before publish for object keys, duplicate field keys, field types, references, workflow states, workflow transitions, and sensitive AI visibility.
- Publish path creates normal `object_types` and optional workflows through existing kernel services.
- Publish writes audit rows and emits an outbox event.
- Template install uses the same governed metadata path; templates are starting points, not special backend objects.
- Built-in Builder templates for CRM, Finance, Procurement, Inventory, and HR.
- Finance template includes normal metadata for accounts, invoices, payments, and budgets, plus sample records, reports, a dashboard, and approval workflow setup.
- Builder endpoints:
  - `GET /v1/builder/drafts`
  - `GET /v1/builder/drafts/:id`
  - `POST /v1/builder/drafts`
  - `POST /v1/builder/drafts/:id/validate`
  - `GET /v1/builder/drafts/:id/publish-preview`
  - `POST /v1/builder/drafts/:id/publish`
  - `GET /v1/builder/templates`
  - `POST /v1/builder/templates/install`

## First-Run Migration (Onboarding)

- Per-tenant migration session that lets a first-time user keep booting their existing ("old") system.
- Live snapshot of the old system: object types, field keys, and active record counts.
- Selectable target ("selected") system from any built-in Builder template (Finance, Procurement, Inventory, CRM, HR).
- Non-destructive old → selected plan: object-by-object, field-by-field mappings with record counts.
- Conflict detection for type mismatches, dropped fields, missing required target fields, and unmapped objects.
- Active-system pointer (`old` or `selected`) that only re-points the session and never moves data.
- On logout, a migration report is emitted for whichever system is active and returned in the logout response.
- Reports are persisted on the session, audited, and emit a `migration.report_generated` event.
- Migration session, start, select, activate, plan, and report endpoints.
- See [MIGRATION_MANUAL.md](MIGRATION_MANUAL.md) for the full guide.

## Dynamic Data Model

- Dynamic object types defined as metadata, not fixed application tables.
- Typed fields: text, long text, number, money, boolean, date, datetime, enum, record reference, user reference, JSON, file reference, and formula.
- Field metadata supports required, display, restricted, unique, indexed, AI-visible, read roles, and write roles.
- Object type create, update, get, and list operations.
- Record create, get, list, update, archive, and restore operations.
- Record validation against published object schemas.
- Record relations and relation lookup.
- Schema-aware Records UI with generated create-record forms.
- Required fields are enforced by the kernel after publish.

## Identity And Access

- Tenant bootstrap with an initial admin user.
- Login, token authentication, and logout.
- Password hashing and token hashing.
- Users, roles, role assignment, service accounts, and API keys.
- Built-in system roles plus installable business-module roles.
- RBAC authorization on kernel service paths.
- Field-level restrictions for sensitive fields.
- Record-level own-scope permission behavior.
- Platform-admin support.

## Workflow And Approvals

- Workflow definitions with states, initial state, transitions, and terminal states.
- Records start in the workflow initial state.
- Available-transition lookup per record.
- Transition execution through the kernel.
- Approval-gated transitions with pending approval records.
- Approval lookup, pending approval listing, and approve/reject decisions.
- Tasks with create, list, get, and complete operations.
- Builder can publish objects with workflow metadata.
- Agent action execution remains approval-gated where required.

## Audit And Events

- Mutation audit rows written atomically with business changes.
- Standalone audit logging for reads, denials, AI operations, Builder draft saves, Builder publish, and template installs.
- Audit query endpoint with filters.
- Permission-denial auditing.
- Outbox-style events with emit, pending, and mark-processed operations.
- Builder publish emits an object-published event.
- AI audit metadata includes provider/model/token data, retrieved source ids, risk score, and approval id fields.

## Analytics

- Permission-aware aggregations over records with filters.
- Saved report definitions.
- Report execution by saved key or ad hoc definition.
- Grouped report results.
- Saved dashboards with report and agent cards.
- Metrics respect tenant scope, RBAC, record scope, and restricted-field behavior.
- Builder-installed templates can create normal saved reports and dashboards.

## AI

- Optional AI layer gated by feature flags.
- Runtime AI provider must be configured; no silent placeholder provider in production.
- Deterministic offline provider is available only when explicitly selected.
- OpenAI-compatible provider path behind the `openai` feature.
- Permission-aware retrieval reads only through kernel services.
- AI retrieval respects tenant isolation, RBAC, record scope, field restrictions, and `ai_visible` field metadata.
- Sensitive fields are excluded from AI retrieval by default.
- General grounded Q&A over accessible records.
- Single-record summaries.
- Finance, Procurement, Sales, and BI agents.
- Source-grounded answers with citations and retrieved source records.
- AI answer auditing with provider/model/token metadata.
- Agent action planner supports dry-run before mutation.
- Agent action execution routes through kernel services and requires approval when policy demands it.

## Acceleration

- Optional acceleration registry with CPU fallback.
- Backend detection for CPU, DataFusion, Triton, Burn, and WebGPU compile availability.
- CPU baseline cosine similarity.
- Optimized batch cosine path with parity tests against the baseline.
- Top-k cosine retrieval helper.
- Read-only acceleration status API endpoint.
- Correct behavior when all acceleration is disabled.

## Business Modules

- Installable business-module metadata for CRM, Finance/ERP, Procurement, Inventory/SCM, HCM, Projects, and Contracts.
- Module object types include accounts, contacts, leads, deals, activities, tickets, vendors, invoices, bills, payments, budgets, purchase requests, purchase orders, receipts, warehouses, products, inventory movements, departments, employees, leave requests, candidates, projects, milestones, and contracts.
- Module workflows for invoice approval, purchase request approval, and leave approval.
- Business roles for finance, sales, procurement, HR, executive, and related users.
- Modules install metadata through kernel services rather than separate business tables.

## HTTP API

- Auth endpoints for login, logout (with first-run migration report), and current user.
- First-run migration endpoints: session, start, select target, set active system, plan, and report.
- Tenant, organization, user, role, and API-key endpoints.
- Builder draft, validation, publish, template-list, and template-install endpoints.
- Object type and record CRUD endpoints.
- Record relation endpoints.
- Workflow transition endpoints.
- Task and approval endpoints.
- Audit query endpoint.
- Report and dashboard endpoints.
- AI ask, BI ask, record summary, specialist agent, dry-run, and execute endpoints.
- Acceleration status endpoint.

## UI Console

- Production-style Operations Console served as static UI assets.
- Sidebar areas: Overview, Records, Reports, Approvals, AI Agents, Action Planner, Builder, Schema, and System.
- Overview shows tenant-level operating context and module coverage.
- Records page supports schema-aware tables and generated create-record forms.
- Reports page runs saved reports.
- Approvals page shows pending approval queue.
- AI Agents page shows grounded answers and citation trail.
- Action Planner supports dry-run and approved execution requests.
- Builder page supports governed object definition, validation, publish, and template install.
- Schema page shows published object types and field governance metadata.
- System page shows session and acceleration status.

## Tested Guarantees

- Tenant isolation blocks cross-tenant access.
- Builder drafts are tenant-isolated.
- Duplicate Builder field keys are rejected before publish.
- Builder publish creates normal object types and writes audit rows.
- Template install creates normal dynamic object types and writes audit rows.
- Required field validation works after Builder publish.
- Members cannot configure object types without grants.
- Restricted fields are hidden and protected.
- AI retrieval does not leak restricted fields or non-AI-visible fields.
- Record-level own-scope access is enforced.
- Object mutations emit audit records.
- Workflow transitions and approval behavior are covered.
- Analytics and dashboards persist and run.
- AI-disabled mode returns feature-disabled errors.
- Agent dry-runs do not mutate data.
- Agent execution is approval-gated and audited.
- Acceleration fallback and numerical parity are tested.
- First-run migration plans old → selected mappings, counts, and conflicts without mutating data.
- Logout emits the migration report only when a session exists, and never blocks logout.
