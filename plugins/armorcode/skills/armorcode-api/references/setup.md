# Setup: API keys, profiles, secrets and network

## Contents
1. Choosing the right API key
2. Creating the key in ArmorCode
3. Storing the key safely
4. Creating profiles
5. Hosts and network access
6. Which Claude surface
7. If something doesn't connect

---

## 1. Choosing the right API key

ArmorCode has six key types (**Manage > Integrations > ArmorCode API > Create New Key**). This skill uses two of them:

| Use | Key type | Role and scope |
|---|---|---|
| Reporting, audits, exports, dry runs | **API** | A read-only role (e.g. *Read Only*), scoped to the hierarchy or groups the person needs. Set an expiry. |
| Org and config changes through this skill | **API** | A role with exactly the create/update permissions needed (a custom role, or Account Admin for user management and cross-organization work). Separate key, separate profile, `--mode read-write`. |
| Push-script or CI scan ingestion | **Report Ingestion** | No role; fixed ingestion rights. This skill's uploads use the normal API key instead (see `integrations.md`). |
| Build release gates from CI | **CI/CD** | Only for `/client/build`. |

What you should know about API keys:
- **An API key carries the role chosen when it was created**, not the creator's current role. It also carries the scope chosen then:
  - **Account Level Access** covers all organizations.
  - **Hierarchies** resolve to whatever groups and subgroups sit under those nodes when the key is used, so new groups are included automatically.
  - **Groups/Subgroups** is fixed to the exact selection.
  - Hierarchies and Groups/Subgroups can't be combined on one key.
- A key whose role is **Account Admin** bypasses per-route permission checks. Use one only when needed: user management requires it, and cross-organization work also needs Account Level Access.
- When the user who created a key is deleted, their keys stop working (401).
- The key is shown once. Creating a key requires the **Create Tools** permission.
- ArmorCode's guidance: one key per integration, least-privilege scope, an expiry, and regular rotation.

A 403 means the key's role or scope doesn't allow that call, or the wrong key type was used. A 404 can also mean the object is outside the key's scope.

## 2. Creating the key in ArmorCode

1. Log in, go to **Manage > Integrations**, find **ArmorCode API**, and click **Create New Key**. If the button is disabled, the user's role lacks Create Tools.
2. Name it after its purpose and the person, e.g. `claude-readonly-jdoe`. Choose type **API**, a role, an expiry and a scope.
3. Copy the key once, straight into the secret store from step 3. **Never paste it into the chat.**

Docs: https://support.armorcode.com/hc/en-us/articles/19447589108499-Generating-ArmorCode-API-Key

## 3. Storing the key safely

`ac.py` reads the key from one of three places. The key never appears in commands, output, plans or logs.

**Environment variable (any OS).** Add it to the shell profile so every new terminal has it. On macOS that is `~/.zshenv`; `~/.zshrc` isn't read by non-interactive shells.
```bash
export ARMORCODE_TOKEN="<paste here, in your editor, not in the chat>"
```
Open a new terminal. Check it exists without printing it: `test -n "$ARMORCODE_TOKEN" && echo set`.

**macOS Keychain (recommended on Macs: not stored as plain text).**
```bash
security add-generic-password -s armorcode-prod -a "$USER" -w
```
The `-w` with no value makes `security` prompt for the key, so it never enters shell history.

**Windows / Linux:** use an environment variable set through your normal secret tooling (a vault agent, `pass`, a CI secret). Keychain integration is macOS-only.

**File (fallback).** Put the key alone in a file and run `chmod 600` on it. `ac.py` refuses a file other users can read.

If the user pasted a key into the chat anyway, don't use it. Explain that it is now in the conversation history, recommend revoking it in **Manage > Integrations**, and help them create and store a new one.

## 4. Creating profiles

A profile names a tenant, where its key lives, and whether changes are allowed. Profiles live in `~/.armorcode/profiles.json`, mode 600, and never contain the key.

```bash
ac.py profile add prod    --token-env ARMORCODE_TOKEN       --label PRODUCTION --default
ac.py profile add prod-rw --token-keychain armorcode-prod-rw --mode read-write --label "PRODUCTION (changes)"   # a second, change-capable key in its own Keychain item
ac.py profile add sandbox --token-env ARMORCODE_SANDBOX      --mode read-write --label SANDBOX \
                          --base-url https://<customer>.armorcode.com
ac.py profile list
ac.py --profile prod ping
```

- Profiles are **read-only unless `--mode read-write`**. Create a read-write profile only when the user asks to make changes, and give it a clear label. The label is printed on every plan.
- `--business-unit ID` pins the organization (business unit) for tenants with several. `ac.py bus` lists them.
- `ARMORCODE_PROFILE=name` or `--profile name` picks a non-default profile.
- `ARMORCODE_HOME` relocates the state directory (`profiles.json`, `plans/`, `backups/`, `audit.jsonl`, `spec/`). Everything there is written with owner-only permissions.

## 5. Hosts and network access

| Deployment | Base URL |
|---|---|
| US SaaS | `https://app.armorcode.com` (default) |
| EU SaaS | `https://eu.armorcode.com` |
| Private instance | `https://<customer>.armorcode.com` |

The machine running Claude's commands needs outbound HTTPS to that host and to the cloud storage URL that scan uploads use. On a corporate proxy or VPN, `ac.py` uses the standard `HTTPS_PROXY` variable.

Rate limits that ArmorCode publishes: **2,000 requests/min per key, 200/min per endpoint, about 2 concurrent requests per key**, and all keys in a tenant share one quota. `ac.py` runs requests one at a time. It slows down when `X-Rate-Limit-Remaining` gets low and honors `X-Rate-Limit-Retry-After-Seconds`. On a 429 without that header (the concurrency limit), it backs off exponentially with jitter. When many integrations share a tenant, schedule large jobs off-peak.

## 6. Which Claude surface

| Surface | Works? | Notes |
|---|---|---|
| Claude Code (CLI, desktop, IDE) | Yes, recommended | Install as a plugin to get the approval hooks (see the README that ships with the plugin). |
| Claude Desktop / Cowork | Yes | Cowork runs plugin hooks too. Make sure the key's environment variable or Keychain item is visible to it. |
| claude.ai (web) | Reference and drafting only, with no live calls, unless an admin allows network egress to your ArmorCode host | The sandbox can't read your local environment variables or Keychain. Don't paste keys there to work around it. |

## 7. If something doesn't connect

| Symptom | Cause | Fix |
|---|---|---|
| `Environment variable X is not set` | The shell that runs commands didn't load it | Put the export in `~/.zshenv` (macOS) or the shell profile, then open a new terminal |
| HTTP 401 | Wrong, expired or revoked key, or a key for another tenant | Create a new key; check the base URL |
| HTTP 403 on every call | Wrong key type (e.g. Report Ingestion), or the role lacks read rights | Use an API-type key with a suitable role |
| HTTP 403 on some writes | The role lacks that create/update permission | See `access.md` for the permission names |
| `network error` / timeout | Proxy, VPN, sandbox egress | Run from a machine that can reach the host; set `HTTPS_PROXY` |
| `ping` shows several organizations | Multi-organization tenant | Pin one with `--business-unit` |
