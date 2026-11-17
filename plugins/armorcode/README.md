# ArmorCode

Work with your ArmorCode tenant in plain language: report on findings and risk, build and clean up your org hierarchy, map repositories, manage teams, and triage findings in bulk. Every change is planned first, shown to you as a dry run, applied only after you approve it, then verified, with automatic backups and a local audit log.

Published by ArmorCode. Source, issues and releases: https://github.com/armor-code/armorcode-skills

## What's inside

- **`armorcode-api` skill:** tells the agent how to work with the ArmorCode REST API safely, with references for the org model, findings, AQL, access control, governance, integrations and every endpoint the skill uses.
- **`ac.py`:** a dependency-free Python 3.8+ command-line tool, bundled with the skill, that makes the API calls. It enforces the guardrails itself: read-only profiles, signed plans, confirmation codes, change caps and verification.
- **Approval hook** (Claude Code and Cowork): asks you before any change is sent to ArmorCode, and blocks commands that would print your API key or edit the tool's local state directly.

## Setup

1. In ArmorCode, go to **Manage > Integrations > ArmorCode API > Create New Key**. Choose key type **API**, a read-only role to start, a scope and an expiry.
2. Store the key outside the chat: in an environment variable such as `ARMORCODE_TOKEN`, or in the macOS Keychain. On Windows, add it under *Edit environment variables for your account*. Never paste a key into a chat.
3. Ask: *"Set up the ArmorCode skill for our tenant using the ARMORCODE_TOKEN variable."* The agent creates a read-only profile and checks the connection.

Python 3.8 or later must be installed where the agent runs commands.

## What it runs, sends and stores

- **Runs:** `ac.py` with Python, when the skill needs the API. The approval hook runs `hooks/guard.py` with Python before tool calls in Claude Code and Cowork; it reads only local files and makes no network calls. On macOS, profiles that keep the key in the Keychain run the system `security` tool to read it.
- **Connects to:** only the ArmorCode host in your profile (`app.armorcode.com`, `eu.armorcode.com` or your private instance), over HTTPS. Scan uploads also send the scan file you chose to the one-time signed cloud-storage URL that ArmorCode returns for that upload, without the API key. The plugin sends nothing to any other destination.
- **Reads your API key** from the environment variable, Keychain item or owner-only file you name in a profile. The key is sent only to that profile's ArmorCode host, never printed, logged or written to disk by the plugin, and never sent across a redirect.
- **Stores locally** in `~/.armorcode/`, with owner-only permissions: profiles (without keys), change plans, backups taken before changes, a cache of your tenant's API spec, and an audit log of applied changes. Delete the folder at any time.
- **Data in your conversation:** API results the agent reads enter the model's context, under your organization's agreement with your AI provider. Finding text can include names and emails of developers in your tenant. Use scoped, read-only keys and file exports to limit what the agent sees.

## Using it is your call

The guardrails reduce the risk of mistakes but don't eliminate it: an agent can misread a request, and the API can change. Start with a read-only key, try changes in a non-production tenant, and read every plan before you approve it. Changes are made with your API key and count as your changes.

## License

Apache License 2.0. "ArmorCode" is a trademark of ArmorCode Inc.
