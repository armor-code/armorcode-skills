# Changelog

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
