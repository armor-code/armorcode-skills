# ArmorCode for Claude

Work with your ArmorCode tenant from Claude in plain language, safely enough for production.

> "Show me open critical findings on external-facing apps under the Payments hierarchy, by group."
> "Export our org hierarchy to a file I can keep in git, then add a new product line with three subgroups."
> "Map these 40 repositories to their subgroups."
> "Mark these 212 findings as false positive, but pilot it on one group first."

The plugin contains one Agent Skill, **`armorcode-api`**. It ships with a dependency-free Python CLI that talks to the ArmorCode REST API with guardrails built in, and the skill tells Claude how to use it safely. In Claude Code, the plugin also installs a hook that makes Claude ask you before any change is sent.

## What it can do

- **Report:** finding counts and breakdowns by group, tool, severity or developer; exports to CSV/JSON; AQL checked against your live tenant before use.
- **Organize:** groups, subgroups, hierarchy tags, tiers and risk tags, owners and teams. Includes a **hierarchy-as-code** workflow: export to a file, edit, review a diff, apply.
- **Clean up:** lint the hierarchy for gaps, duplicates and cross-placements; consolidate groups; map SCM repositories to subgroups, one at a time or from a CSV.
- **Triage:** bulk status or severity changes and moves between subgroups, each counted first, capped, verified and reversible.
- **Accept risk properly:** exceptions created per group from one AQL, then submitted, approved and archived, with reasons, reviewers and expiry.
- **Integrate:** scan uploads (with the replace-semantics warning), tool and ticket mappings, runbooks, saved views, dashboards and the audit log.

## How it keeps production safe

| Guardrail | What it means |
|---|---|
| Read-only by default | Profiles are read-only unless you deliberately create a read-write one. A read-only profile can plan, but never apply |
| Plan, approve, apply | Every change is first written as a plan and shown as a dry run: tenant, risk level, exact diff, warnings. It runs only after you approve that specific plan, using a confirmation code |
| Approval prompt (Claude Code / Cowork) | A hook asks you before any `apply`, any direct write to your ArmorCode host, or any ArmorCode MCP write tool, whatever Claude decided |
| Blast-radius limits | Bulk finding changes over 1,000 findings, deletes and purges need an extra explicit flag |
| Automatic backups | Groups, subgroups and teams are re-read and saved just before they change. Findings plans record prior values, so `findings-revert` can undo them. Repository plans record previous mappings |
| Verification | After each change, the CLI re-reads the object, polls async jobs and reports partial failures, instead of trusting an HTTP 200 |
| Quirk-aware helpers | The CLI handles the API's full-replace endpoints, silently ignored filters, tag casing, team-member replacement and deletes that report success but haven't finished |
| Audit trail | Every applied step is logged locally (`~/.armorcode/audit.jsonl`), in addition to ArmorCode's own audit log |
| Key never shown | The API key is read from an environment variable, the macOS Keychain or a 0600 file. It is never printed, logged or written into plans, and never sent across a redirect |
| No side doors | The CLI refuses to send any change outside `apply`, and plans are signed per machine, so a plan edited after review won't run |

## Requirements

- Python 3.8+ on the machine where Claude runs commands.
- HTTPS access to your ArmorCode host: `app.armorcode.com`, `eu.armorcode.com` or your private instance.
- An ArmorCode **API**-type key. Use read-only for reporting, and a separate key for changes. See *Setup* below.

## Install

### Claude Code (recommended)
```
/plugin marketplace add <this repository's URL or local path>
/plugin install armorcode@armorcode
```
Administrators can preinstall it for everyone through managed settings (`extraKnownMarketplaces` and `enabledPlugins`).

### Claude Desktop, Cowork or claude.ai
Upload `dist/armorcode-api.zip` under your skills settings (Settings > Capabilities/Customize > Skills), or have an organization admin add it to the org skill library.
- On claude.ai, live calls need network access from the code sandbox to your ArmorCode host. Without it, use the skill for planning and review only.
- Hooks don't run in plain chat, so the guardrails there rest on the skill's plan and apply flow.

## Setup (five minutes)

1. In ArmorCode, go to **Manage > Integrations > ArmorCode API > Create New Key**. Choose type **API**, a read-only role, a scope (hierarchy or groups) and an expiry.
2. Store the key outside the chat, either in an environment variable (e.g. `export ARMORCODE_TOKEN=…` in `~/.zshenv`) or in the macOS Keychain:
   ```
   security add-generic-password -s armorcode-prod -a "$USER" -w
   ```
3. Ask Claude: *"Set up the ArmorCode skill for our production tenant using the ARMORCODE_TOKEN variable."* Claude creates a read-only profile and checks connectivity.
4. When you want changes, create a second, change-capable key and ask Claude for a read-write profile labelled clearly (e.g. "PRODUCTION (changes)").

Never paste an API key into the chat. If one is pasted, revoke it and create a new one.

## Data handling

- The CLI runs on your machine (or the environment where Claude runs commands) and calls **your** ArmorCode host directly. Neither the skill nor ArmorCode receive the key or your data through any other service.
- API responses that Claude reads enter its context, and are handled under your organization's agreement and data settings with Anthropic. Use scoped, read-only keys and `--out` files to limit what Claude sees.
- Local state lives in `~/.armorcode/` with owner-only permissions: profiles (no keys), plans, backups, the spec cache and the audit log. Delete it at any time.
- The skill tells Claude to treat finding text, tags and comments as untrusted data, never as instructions.

## Testing

```
python3 tests/test_cli.py      # CLI safety logic (offline)
python3 tests/test_guard.py    # approval-hook decisions (offline)
python3 tools/build.py --check # skill spec validation
```

Before each release, the maintainers also run a live regression against a non-production tenant. It creates, changes and removes clearly named test objects through every planner.

## Updating and support

- The plugin, skill and CLI share one version (see `CHANGELOG.md`). Update with `/plugin update armorcode`, or re-upload the zip.
- Questions or unexpected API behavior: contact ArmorCode Support with the command, the plan id and the time. Never include the API key.

## Repository layout

```
.claude-plugin/marketplace.json          marketplace (one plugin)
plugins/armorcode/.claude-plugin/plugin.json
plugins/armorcode/hooks/                 approval-prompt hook (Claude Code / Cowork)
plugins/armorcode/skills/armorcode-api/  the skill: SKILL.md, references/, scripts/ac.py, assets/
tools/build.py                           validates the skill and builds dist/armorcode-api.zip
tests/                                   offline tests: guardrail hook decisions and CLI safety logic
evals/                                   behavior test prompts for the skill
```
