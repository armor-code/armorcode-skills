# Troubleshooting

## Contents
1. HTTP status codes
2. Error messages and what they mean
3. Success responses that didn't do what you think
4. Timing: async work and index lag
5. Rate limits
6. When to involve ArmorCode Support

---

## 1. HTTP status codes

| Status | Meaning | What to do |
|---|---|---|
| 400 | Bad request, or a business rule failed. Also "object in another organization" | Read the `message`, then see §2. Don't retry unchanged |
| 401 | Key missing, invalid, expired or revoked (or its creator was removed) | A new key; check the base URL |
| 403 | The key's role or scope doesn't allow this, or the wrong key type | `access.md` permission table; use an API-type key |
| 404 | Wrong path, or the object is outside the key's scope | `ac.py spec search`; check the key's scope |
| 409 | Conflict, e.g. "Runbook N is already running" | Wait for the running job |
| 429 | Rate or concurrency limit | `ac.py` retries automatically (§5) |
| 500 with no message | Often a missing required field on an Internal endpoint (e.g. `repoType` on a repository mapping) | Compare your body with a record read from the same endpoint |
| Network error on a write | The request may or may not have been processed | **Re-read before retrying**; never resend a write blindly |

## 2. Error messages and what they mean

| Message (abridged) | Cause | Fix |
|---|---|---|
| `Product Not Found` | The group is in another organization (often Archive) or outside the key's scope | Check `businessUnitId`; skip it. It isn't corrupt |
| `Wide range update detected. Missing N% of fields` | A PUT on a group or subgroup left out more than 30% of its populated fields | Use `plan group-update` / `subgroup-update` (read-merge-write) |
| `Expected a numeric ID for field 'product'` | AQL with a group name | `product = <id>`; ids from `ac.py groups --search` |
| `Column 'X' not supported for FINDINGS` | Wrong AQL field (`title`, `environmentName`, `group`, `subGroup`, `developerName`) | `aql.md` field table |
| `Operator '[=]' is not supported for column 'tags'` | Tags need match operators | `tags matchAny ('k:v')` |
| `Invalid status value: Remediated` | UI wording in AQL | `MITIGATED` (UI Remediated), `CONTROLLED` (UI Mitigated) |
| `Invalid value 'High'` (bulk update) | Severity case | `HIGH`, `CRITICAL`, … |
| `Note cannot be left blank` | Bulk finding update without `notes` | Add `--note` |
| `Product, Sub-product and Environment should either all be null or all be not null` / `Invalid Environment` | Finding move missing a field, or an environment id from another subgroup | `plan findings-move` resolves the target's environment |
| `Scan date cannot be set to a future date` | `scanDate` ahead of server time (UTC) | Omit it (the default is now minus 1 h) |
| `unsupported file format : <file> for tool <tool>` | Wrong extension for that tool's parser | `integrations.md` §3 |
| `Invalid JSON submitted` | CUSTOM / Pentest upload not a top-level array, or an item without `title` | Send `[ {...}, … ]` |
| `Configuration already exists` | Tool allows one mapping per subgroup (+ environment): GitLab, Qualys | Edit the existing mapping (comma-join projects/hosts) |
| `Ticket Configuration already exists for this mapping` | Group already mapped in another tracker | Remove it from the other mapping first |
| `no findings are associated` (exception submit) | In-scope findings still attaching | Wait 1–2 minutes, then submit |
| `Name already exists` | Group or subgroup name taken (unique per organization / per group) | Choose another name, or update the existing one |
| `Role name should not start or end with…` | Role-name rules | Letters, digits, space, `_`, `-` only |

## 3. Success responses that didn't do what you think

All of these have happened. `ac.py` guards against most of them; know them when you read raw output.

| Symptom | Reality | Guard |
|---|---|---|
| A filtered search or count returns everything | Unknown `filters` key, string boolean (`"true"`), or a top-level `aqlQuery`: all **silently ignored** | `ac.py` refuses these; prefer `--aql` |
| A plain-filter count or change matches 0 | Filter values are case-sensitive: severity `Critical`, status `OPEN`, source `Wiz` | `ac.py` refuses wrong-case severity/status; prefer AQL |
| `/api/sub-product/list` returns other groups' subgroups | You sent `productIds`; this endpoint wants `productId` (array) | Use `ac.py subgroups --group` |
| Bulk finding update returns 200 but nothing changed | Async job still running, a job with `failedFindingIds`, a missing per-status permission, or fuzzy `id` instead of `id_term` | `apply` polls the job and re-reads samples |
| `PUT /api/team` returns 200, members unchanged | Member changes are ignored on that route | `plan team-members` uses `/with-user` |
| `DELETE /api/team/{id}` returns 200, team still exists | The team still had members | Empty it first; `apply` checks the object is gone |
| Group tier shows "N/A" | `tier` was sent as a name | Send the tier id; `--tier` checks it |
| Tier changed but risk score didn't | The API doesn't write tier risk tags | `--tier-tags` |
| Custom tool upload shows PASSED but 0 findings, or fields missing | Named custom tools apply their field mapping only to CSV; JSON ignores it | Upload CSV |
| Upload "lost" findings | Replace semantics: absent findings were MITIGATED | One complete file per tool + subgroup + environment |
| Ticket template created (200 + id) but invisible | Created without `businessUnitId` | Include it |
| Dashboard created but empty and un-editable | `widgetConfig` sent as a string | Send `widgetConfigJsonNode` (list) |
| Deleting a tool mapping removed its findings | `deleteAllData` defaults to true | `ac.py` requires an explicit value |
| A bulk change keeps being re-applied to new findings | `rulesOnFutureFindingsEnabled: true` created a standing rule | Never set it unless intended |

## 4. Timing: async work and index lag

| Operation | Typical settle time | How to confirm |
|---|---|---|
| Bulk finding update or move | Job finishes in seconds to minutes; per-finding GET within seconds; search and counts up to ~1 min | Job status, then `findings get`, then counts |
| Group change → subgroup inherited tags | Seconds | `ac.py hierarchy` shows it first |
| Group hard delete | Seconds | `apply` waits up to 60 s |
| Scan upload | Seconds to many minutes (processed in order) | `ac.py scans --file NAME` |
| Exception scope attachment | 1–2 minutes | Exception detail |
| AI correlation | Nightly | Next day |
| Tool mapping delete | Async ("submitted") | Re-list mappings |

Don't conclude failure from an early re-read, and don't stack bulk changes on the same findings before the previous one settles.

## 5. Rate limits

- Published limits: **2,000 requests/min per key**, **200/min per endpoint** (URL + method), about **2 concurrent requests per key**, and one quota shared by all keys in the tenant.
- A 429 with `X-Rate-Limit-Retry-After-Seconds` means the quota was hit: wait that long. A 429 **without** it, with the body "Too many concurrent requests", means the concurrency limit: back off exponentially with jitter.
- `ac.py` does both, works sequentially, and pauses when `X-Rate-Limit-Remaining` drops to 5 or below.
- Large jobs:
  - Prefer bulk endpoints over loops.
  - Expect about 200 calls/min to any single endpoint; one GET per group means ~5 minutes per 1,000 groups.
  - Run during quiet hours if other integrations share the tenant.

## 6. When to involve ArmorCode Support

- A 400 that persists with a correct body (an unexposed business rule), or a 500 that repeats.
- Backend-only settings:
  - severity filters on some connectors (Wiz keeps Critical/High by default);
  - host-aware deduplication for VM tools;
  - exception status flags;
  - rate-limit increases.
- Restoring something from Archive, or anything that needs a purge undone.
- Send: the endpoint, request body (no key), response body, time (UTC), and the tenant URL.
