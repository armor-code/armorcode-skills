# Changelog

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
