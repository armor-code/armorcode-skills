# Changelog

## 1.2.0 — 2026-11-16

API behavior verified live on ArmorCode tenants, and checked against ArmorCode's code and published API reference.

- **SLA policies** (`governance.md` §3, rewritten):
  - Policies live at `/api/sla/template`; the legacy `/api/sla/config` returns `[]`.
  - Durations are **milliseconds**, not days as 1.1.0 said.
  - Create a policy, assign it to a group with the new `plan group-update --sla-template-id`, and apply it to existing findings with `POST /api/sla/template/{id}/recalculate`. Recalculate is the UI's Save & Apply: it creates a new template id and takes effect at the next daily recalculation.
- **Jira without the UI** (`integrations.md` §6):
  - A complete mapping body.
  - The `"webhook": true` PUT for two-way status sync, and how to verify it.
  - `resolvedStatus`/`reopenStatus` must exist in the project workflow.
  - Moving groups between projects.
  - Custom-field mapping, and which template variables render well or badly.
  - Template updates with `PUT …/ticketUnifiedTemplate/{id}`.
  - MULTI templates and grouped tickets (one issue for up to 50 findings).
- **Runbooks** (`governance.md` §2):
  - A scheduled digest (`FINDING_SCHEDULE_REPORT`): Quartz cron with seconds, `timeZone`, and `finding/email` (one digest) vs `finding/createEmail` (one email per finding).
  - Fixed trigger input ids.
  - The lowercase `groupBy` keys (`cves`, not `cve`).
  - Ticket template ids on `createTicket`.
- **Scan uploads:**
  - **Uploads of one tool to one subgroup no longer overlap.** Overlapping uploads don't deduplicate against each other. `plan scan-upload` warns when an earlier upload is still processing. `apply` waits for it to finish, and stops without sending if it doesn't.
  - New notes for Prisma Cloud Compute CSV (image vs host files, and the `Hostname` dedup trap), Prisma Cloud Redlock JSON, and Tenable CVSS v3, plugin output and `tenable.plugin.family`.
  - A recipe for scanners that aren't listed.
  - Custom tool names must start with `custom-`.
- **Accept Risk, corrected** (`findings.md` §5):
  - The full direct body.
  - `unsupressAfterDuration` is epoch **seconds**. A millisecond value passes validation but never resurfaces the findings.
  - `PUT /api/findings/bulk` isn't supported.
- **Dashboards** (`governance.md` §5):
  - `PUT /api/custom-dashboard/{id}` exists (1.1.0 said there was no full-dashboard PUT).
  - System dashboards can't be edited by API.
  - Risk trend widgets need `aggregateBy: "Day"` until a week of snapshots exists.
  - Team widgets need each group's assigned team.
- **AQL:** `groupTier`, `baseScore`, `CVSSVector`, `assetOwner`, and `slaDueDate` with `'now()'` arithmetic. Also the names that are rejected (`tier`, `dueDate`, `slaStatus`, …).
- **Correlation:**
  - A read-only inventory recipe, grouping by `correlationId`.
  - `HostName:` remediation groups.
  - `source`/`scanType` can be lists in raw JSON.
- **Also:**
  - Exceptions' `acceptRiskOnExpiry` acts on approval.
  - CMDB asset imports.
  - GitLab repository matching and sync limits.
  - Organization renames are UI-only.
  - Group owners read back with email and name.
- **Endpoint catalog:** new rows for SLA, dashboard, risk trend and ticket-template endpoints. Every label was re-checked against the published API reference; endpoints not in it are marked Internal (may change without notice).

## 1.1.0 — 2026-11-16

First public release, from github.com/armor-code/armorcode-claude, under the Apache License 2.0.

- **Install from GitHub.** In Claude Code, `/plugin marketplace add armor-code/armorcode-claude` then `/plugin install armorcode@armorcode`; updates arrive with `claude plugin marketplace update armorcode`. Desktop zips and the getting-started PDF are attached to each GitHub Release.
- **Windows support:**
  - The approval hook finds Python as `python3`, `python` or `py`, so it no longer needs `python3` on the PATH. If no Python 3.8+ is found, it warns instead of blocking every command.
  - `ac.py` no longer refuses key files on Windows because of POSIX permission bits that Windows doesn't have.
  - The macOS Keychain option now explains that it's macOS-only and points to `--token-env`.
  - Output can't crash a Windows console with a legacy code page.
  - Setup docs cover storing the key as a Windows user environment variable and running `ac.py` with `python` or `py -3`.
- **Hook false positives fixed:** commands that mention a hostname like `www.armorcode.com`, or that discard output with `2>/dev/null` or `2>&1`, are no longer mistaken for edits to the local state folder `~/.armorcode`.
- Tests run on macOS, Windows and Linux in CI.

## 1.0.0 — 2026-10-23

First release of the ArmorCode plugin for Claude.

- **`armorcode-api` skill** with a safety contract:
  - read-only by default;
  - every change goes plan → approve → apply;
  - finding text is treated as untrusted;
  - the API key is never shown.
- **`ac.py` guarded CLI** (Python 3.8+, standard library only):
  - profiles per tenant, with keys from an environment variable, the macOS Keychain or a 0600 file;
  - reads: groups, subgroups, hierarchy tree and lint, findings count/breakdown/list/export, AQL validation, scans, repositories, teams, users, roles, and the tenant's own OpenAPI spec;
  - planners: group and subgroup create/update (read-merge-write), subgroup moves, hierarchy-as-code sync, repository mapping (single or CSV), team membership, bulk finding status/severity changes and moves (capped, with revert), scan upload, restore from backup, and raw requests with risk classification;
  - apply: confirmation codes, plan expiry, resumable multi-step plans, automatic backups, post-change verification (including async jobs and "deleted but still there" checks), and a local audit log;
  - planners for exceptions: one per group from a single AQL, plus submit/approve/reject/archive;
  - `findings count --by FIELD`, `--org`, and `aql-check` that breaks down zero-match queries;
  - hard write gate: no change is ever sent outside `apply`, and read-only profiles can't apply;
  - plans signed per machine, redirects never followed with the key, https only;
  - `plan raw` gets the same guards: filter-key checks, counts, the 1,000 cap, and refusing standing rules or runbook backfills without an explicit flag;
  - handles rate limits as ArmorCode documents them: the 429 retry header, backoff with jitter, and proactive slow-down.
- Offline tests (`tests/`) for the CLI's safety logic and the hook's decisions.
- **Approval hook for Claude Code and Cowork.** It asks before `apply`, before direct write requests to ArmorCode hosts, and before ArmorCode MCP write tools, showing the plan's steps. It blocks commands that would print the API key, and edits to the CLI's local state outside `ac.py`.
- **References:** setup and key types, org model and hierarchy, findings, AQL v2 (live-validated), access control, governance, integrations, troubleshooting, and an endpoint catalog with Public/Internal stability labels.
