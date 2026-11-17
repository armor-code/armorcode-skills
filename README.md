# ArmorCode for AI agents

Work with your ArmorCode tenant in plain language from Claude, Codex, GitHub Copilot, Cursor, Gemini, Grok and other AI agents, with guardrails that show you every change before it happens.

> "Show me open critical findings on external-facing apps under the Payments hierarchy, by group."
> "Export our org hierarchy to a file I can keep in git, then add a new product line with three subgroups."
> "Map these 40 repositories to their subgroups."
> "Mark these 212 findings as false positive, but pilot it on one group first."

The plugin contains one [Agent Skill](https://agentskills.io), **`armorcode-api`**. It ships with a dependency-free Python CLI that talks to the ArmorCode REST API with guardrails built in, and the skill tells the agent how to use it safely. It's packaged in the open formats that today's agents read: Agent Skills, [Agent Plugins 1.0](https://agent-plugins.org), and the Claude Code plugin format. Where the agent runs plugin hooks, a hook also stops key leaks and asks you before any change is sent.

**Quick start:**

| Agent | Commands |
|---|---|
| Claude Code | `/plugin marketplace add armor-code/armorcode-skills` then `/plugin install armorcode@armorcode` |
| OpenAI Codex | `codex plugin marketplace add armor-code/armorcode-skills` then `codex plugin add armorcode@armorcode` |
| GitHub Copilot CLI | `copilot plugin marketplace add armor-code/armorcode-skills` then `copilot plugin install armorcode@armorcode` |
| Any other agent | `npx skills add armor-code/armorcode-skills` (Gemini CLI, Cursor, Windsurf, OpenCode, Cline and 70+ more) |

Then ask your agent: *"Set up the ArmorCode skill for our tenant using the ARMORCODE_TOKEN variable."* More options, including desktop apps: see [Install](#install).

## What it can do

- **Report:** finding counts and breakdowns by group, tool, severity or developer; exports to CSV/JSON; AQL checked against your live tenant before use.
- **Organize:** groups, subgroups, hierarchy tags, tiers and risk tags, owners and teams. Includes a **hierarchy-as-code** workflow: export to a file, edit, review a diff, apply.
- **Clean up:** lint the hierarchy for gaps, duplicates and cross-placements; consolidate groups; map SCM repositories to subgroups, one at a time or from a CSV.
- **Triage:** bulk status or severity changes and moves between subgroups, each counted first, capped, verified and reversible.
- **Accept risk properly:** exceptions created per group from one AQL, then submitted, approved and archived, with reasons, reviewers and expiry.
- **Integrate:** scan uploads (with the replace-semantics warning), tool and ticket mappings, runbooks, saved views, dashboards and the audit log.

## Guardrails

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

## Using it is your call

The guardrails above reduce the risk of mistakes; they don't eliminate it. An AI agent can misread a request, and the ArmorCode API can change. You decide whether to use the skill, which tenants and keys to use it with, and whether to approve each change. Changes made through it are made with your API key and count as your changes.

Sensible ways to start:
- Use a **read-only key** first: reporting, exports and planning never change anything.
- Try changes in a **non-production tenant or organization** before using a change-capable key elsewhere.
- **Read every plan** before approving it, and pilot large changes on a small slice.
- Keep keys scoped to what you need (a hierarchy or specific groups), with an expiry.

## Requirements

- Python 3.8+ on the machine where the agent runs commands. macOS and most Linux systems have it. On Windows, install it from python.org (tick *Add python.exe to PATH*) or with `winget install Python.Python.3.12`.
- HTTPS access to your ArmorCode host: `app.armorcode.com`, `eu.armorcode.com` or your private instance.
- An ArmorCode **API**-type key. Use read-only for reporting, and a separate key for changes. See *Setup* below.

## Install

### Plugins (skill plus approval hook)

| Agent | How to install | Hook |
|---|---|---|
| **Claude Code**: terminal, IDE, or the Desktop app's **Code tab** | `/plugin marketplace add armor-code/armorcode-skills`, then `/plugin install armorcode@armorcode` (or **+ > Add plugins** in the Desktop Code tab). From a terminal: `claude plugin marketplace add armor-code/armorcode-skills` and `claude plugin install armorcode@armorcode` | Asks before every change |
| **Claude Desktop: Cowork and chat** | Download `armorcode-plugin-<version>.zip` from [Releases](https://github.com/armor-code/armorcode-skills/releases/latest), then Customize > Plugins > Add > **Upload plugin**. Org admins can upload it once for everyone under Organization settings > Plugins & skills | Cowork only |
| **OpenAI Codex**: CLI, app, IDE | `codex plugin marketplace add armor-code/armorcode-skills`, then `codex plugin add armorcode@armorcode` (or `/plugins` inside Codex) | Blocks key leaks; approvals come from Codex's own approval mode |
| **GitHub Copilot**: CLI | `copilot plugin marketplace add armor-code/armorcode-skills`, then `copilot plugin install armorcode@armorcode` | Not yet |
| **GitHub Copilot**: VS Code | Command Palette > **Chat: Install Plugin from Source**, or add `armor-code/armorcode-skills` as a marketplace under `chat.plugins.marketplaces` | Not yet |
| **Grok Build** | `grok plugin marketplace add armor-code/armorcode-skills`, then `grok plugin install armorcode@armorcode` (Grok Build reads Claude-format marketplaces; not yet tested by us) | Not yet verified |

### Skill only, any agent

- **Any Agent Skills client** (Gemini CLI, Cursor, Windsurf, OpenCode, Cline, Goose, Amp, Kiro and others): `npx skills add armor-code/armorcode-skills`. Add `-a <agent>` to pick agents, `-g` for all your projects. It installs to the shared `~/.agents/skills/` folder or the agent's own.
- **Without Node:** download `armorcode-api-skill-<version>.zip` from [Releases](https://github.com/armor-code/armorcode-skills/releases/latest) and unzip it into your agent's skills folder: `~/.agents/skills/` (Codex, Gemini CLI, Copilot and others), `~/.claude/skills/` (Claude Code), or the folder your agent documents.
- **Chat apps** (claude.ai: Customize > Skills; others where skills upload is offered): upload the same zip. Live calls need the chat's code sandbox to reach your ArmorCode host; otherwise use it for reference and drafting. For live data in chat, ArmorCode's hosted MCP server is the better fit (see ArmorCode's documentation).

Start a new session after installing. Every route needs Python 3.8+ where the agent runs commands.

Where no hook runs, the guardrails rest on the skill's plan-and-approve flow and the CLI's own write gate: read-only profiles, signed plans and confirmation codes. A [getting-started guide](https://github.com/armor-code/armorcode-skills/releases/latest) (PDF) is attached to each release.

## Setup (five minutes)

1. In ArmorCode, go to **Manage > Integrations > ArmorCode API > Create New Key**. Choose type **API**, a read-only role, a scope (hierarchy or groups) and an expiry.
2. Store the key outside the chat:
   - **macOS:** the Keychain (`security add-generic-password -s armorcode-prod -a "$USER" -w` prompts for it), or `export ARMORCODE_TOKEN=…` in `~/.zshenv`.
   - **Linux:** an environment variable from your usual secret tooling.
   - **Windows:** Start menu > *Edit environment variables for your account* > New: `ARMORCODE_TOKEN`. Then quit and reopen your AI app.
3. Ask your agent: *"Set up the ArmorCode skill for our tenant using the ARMORCODE_TOKEN variable."* It creates a read-only profile and checks connectivity.
4. When you want changes, create a second, change-capable key and ask the agent for a read-write profile labelled clearly (e.g. "PRODUCTION (changes)").

Never paste an API key into the chat. If one is pasted, revoke it and create a new one.

## Data handling

- The CLI runs on your machine (or the environment where the agent runs commands) and calls **your** ArmorCode host directly. Neither the skill nor ArmorCode receive the key or your data through any other service.
- API responses that the agent reads enter the model's context, and are handled under your organization's agreement and data settings with your AI provider. Use scoped, read-only keys and `--out` files to limit what Claude sees.
- Local state lives in `~/.armorcode/` with owner-only permissions: profiles (no keys), plans, backups, the spec cache and the audit log. Delete it at any time.
- The skill tells the agent to treat finding text, tags and comments as untrusted data, never as instructions.

## Testing

```
python3 tests/test_cli.py      # CLI safety logic (offline)
python3 tests/test_guard.py    # approval-hook decisions (offline)
python3 tools/build.py --check # skill spec validation and version agreement
```

CI runs these on macOS, Windows and Linux for every push and pull request. Before each release, the maintainers also run a live regression against a non-production tenant. It creates, changes and removes clearly named test objects through every planner.

## Updating and support

- The plugin, skill and CLI share one version (see [CHANGELOG.md](plugins/armorcode/CHANGELOG.md)).
- **Claude Code:** `claude plugin marketplace update armorcode`, then `claude plugin update armorcode@armorcode`, and restart. You can also turn on auto-update for the marketplace under `/plugin`.
- **Codex:** `codex plugin marketplace upgrade armorcode`. **Copilot CLI:** `copilot plugin update armorcode@armorcode`. **Skills installer:** `npx skills update`.
- **Desktop app:** download the new zip from [Releases](https://github.com/armor-code/armorcode-skills/releases/latest) and upload it again under Customize > Plugins.
- **Problems or ideas:** open an [issue](https://github.com/armor-code/armorcode-skills/issues) with the command, the plan id and the time, or contact ArmorCode Support. Never include an API key or tenant data. Security issues: see [SECURITY.md](SECURITY.md).
- **About the endpoints:** some endpoints the skill uses are ones the ArmorCode web app calls but that aren't in the published API spec yet. They're verified against a live tenant and labelled **Internal, may change** in [the endpoint catalog](plugins/armorcode/skills/armorcode-api/references/endpoint-catalog.md).

## Repository layout

```
.claude-plugin/marketplace.json          marketplace for Claude Code, Copilot CLI and Grok Build
.agents/plugins/marketplace.json         marketplace for Codex
skills.sh.json                           where `npx skills` finds the skill
plugins/armorcode/plugin.json            Agent Plugins 1.0 manifest (Codex, Copilot, VS Code and other conforming clients)
plugins/armorcode/.claude-plugin/plugin.json   Claude Code manifest
plugins/armorcode/hooks/                 approval-prompt hook (Claude Code / Cowork)
plugins/armorcode/skills/armorcode-api/  the skill: SKILL.md, references/, scripts/ac.py, assets/
docs/guide/                              getting-started guide (HTML source; the Release workflow renders the PDF)
tools/build.py                           validates the skill and builds dist/armorcode-plugin-<ver>.zip (+ skill-only zip)
tools/release_notes.py                   release notes from the CHANGELOG
tests/                                   offline tests: guardrail hook decisions and CLI safety logic
evals/                                   behavior test prompts for the skill
.github/workflows/                       CI (3 OSes) and tag-triggered releases
```

## License

[Apache License 2.0](LICENSE). Contributions welcome: see [CONTRIBUTING.md](CONTRIBUTING.md). "ArmorCode" is a trademark of ArmorCode Inc.; the license doesn't grant rights to use it.

