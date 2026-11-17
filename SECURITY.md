# Security

## Reporting a vulnerability

Please report security issues privately, not in a public issue:

- Use **Report a vulnerability** under this repository's **Security** tab (GitHub private vulnerability reporting), or
- contact ArmorCode Support.

Include the plugin version, the agent or app (Claude Code, Codex, Copilot, Cursor, Gemini CLI, a chat app, …), your OS, and steps to reproduce. **Never include an API key, tenant URL or tenant data.** If you think a key was exposed, revoke it in ArmorCode under **Manage > Integrations > ArmorCode API** first.

We'll acknowledge the report, keep you updated, and credit you in the release notes if you'd like.

## What counts

Anything that defeats the plugin's guardrails, for example:

- a change reaching an ArmorCode tenant without going through `ac.py plan` and `ac.py apply`, or without the approval prompt where the hook runs;
- an API key being printed, logged, written to a plan or backup, or sent to a host other than the profile's;
- a plan applying after it was edited, or on a different profile than it was built for;
- tenant data (finding text, tags, comments) steering Claude into an action the user didn't ask for.

## Supported versions

Only the latest release gets fixes. Update through your agent's plugin manager or `npx skills update` (see the README), or use the latest zip from Releases.
