# Findings: counting, exporting, triage, moves, tags, correlation

## Contents
1. Statuses and severities (API vs UI names)
2. Counting and reporting
3. Listing and exporting
4. Filters: what's safe
5. Bulk changes (status, severity, owner, due date)
6. Moving findings between subgroups
7. Finding tags
8. Correlation
9. Recipes: triage at scale, drain a landing zone, reconcile counts, BI export

---

## 1. Statuses and severities

| UI label | API value |
|---|---|
| Open | `OPEN` |
| Confirmed | `CONFIRMED` |
| Triage | `TRIAGE` |
| In Progress | `IN_PROGRESS` |
| **Mitigated** | **`CONTROLLED`** |
| **Remediated** | **`MITIGATED`** |
| Accept Risk | `ACCEPTRISK` |
| False Positive | `FALSEPOSITIVE` |
| Suppressed | `SUPPRESSED` |

The two swapped names cause most "the numbers don't match" questions.

Severities: finding records and the bulk-update API use `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`; the bulk API rejects `High`. AQL values are case-insensitive (`Critical`, `'CRITICAL'`), and stats buckets use title case. `ac.py` normalizes.

**Choosing a status for a bulk change.** Ask the user which one matches reality:

| Situation | Status |
|---|---|
| The scanner is wrong; not a real issue here | `FALSEPOSITIVE` |
| Real, but the business accepts it for a period (e.g. an unfixed base-image CVE) | An **exception** (records owner, reason, expiry), not a bulk status |
| A compensating control is in place (UI "Mitigated") | `CONTROLLED` |
| Hide temporarily, to revisit | `SUPPRESSED` |
| Fixed | Let the next scan close it (`MITIGATED`); setting it by hand hides findings the scanner still reports |

## 2. Counting and reporting

| Need | Command |
|---|---|
| Total plus breakdown by status and severity | `ac.py findings count --aql "…"` |
| Breakdown by any field | `ac.py findings count --aql "…" --by product\|subProduct\|source\|scanType\|environmentName\|developer… [--top N]` |
| Distinct values of a field | `ac.py findings values --field source [--aql …]` |

Behind these is `POST /user/findings/findingStats/all {filters, aggField (default status), secAggField (default severity)}`:
- The response has one bucket per value **plus a separate `Reported` entry, which is the total**. Never add `Reported` to the buckets.
- Group and subgroup buckets are keyed by id; `--by` resolves names.
- Stats count **every** status unless the filter or AQL restricts it. Be explicit: "open critical" means `status IN ('OPEN','CONFIRMED','TRIAGE','IN_PROGRESS')`. Decide with the user whether CONTROLLED (UI Mitigated) counts as open.

`POST /user/findings/findings-filters {fields:[…], filters}` returns value lists, such as `[{id,name}]` for `subProduct`. It's cheap and useful for profiling before a bulk change.

## 3. Listing and exporting

`ac.py findings list --aql "…" [--fields id,severity,status,title,product.name,subProduct.name,…] [--limit N] [--all-statuses] [--out file.csv|.json]`

Behind it is `POST /api/findings?size=1000[&afterKey=N]` with body `{filters, ignoreMitigated}`:
- `size` and `afterKey` are **query parameters**. Rows are at `data.findings`, the cursor at `data.afterKey`. 1,000 per page is the tested size; the default is 10.
- Pagination ends when a page is empty: `afterKey` comes back as `-1` only for an empty page. Never send `-1` back, because a missing or `-1` cursor restarts from page 1 and loops forever. `ac.py` also stops if the cursor stalls.
- **Which statuses come back**:
  - An **AQL** query returns **every status** unless the AQL restricts `status`. That matches what `findings count` reports for the same AQL.
  - Plain `filters` without AQL leave out MITIGATED (UI: Remediated), because `ignoreMitigated` defaults to true. `--all-statuses` sends `ignoreMitigated: false`.
  - Say which statuses you mean ("open" = `status IN ('OPEN','CONFIRMED','TRIAGE','IN_PROGRESS')`).
- Throughput is roughly 300–400 findings/s. For millions of rows, split the export by group (`--aql "product = <id>"`) so each run is bounded and resumable.
- Dates come back as epoch milliseconds; `ac.py` formats `foundOn`/`slaDueDate` as dates.
- Results are limited to what the key's scope can see. Two keys with different scopes give different totals.
- Counts and lists span **every organization the key can see**, Archive included. Add `--org ID` or `--org pinned` to limit them to one organization (the `businessUnit` filter).

One finding: `ac.py findings get ID` (`GET /user/findings/{id}`). It includes `toolSeverity`, `envName`, CVSS, ticket and remediation fields. The finding's UI link is `https://<host>/#/findings/<tenantId>/<buId>/<findingId>`.

## 4. Filters: what's safe

- **Prefer AQL** (`--aql`, sent as `filters.aqlQueryV2`). Check every query first with `ac.py findings aql-check --aql "…"`. A bad query returns the same 400 message the UI shows. Syntax is in `aql.md`.
- Raw `filters` keys are case-sensitive enum names, such as `severity`, `status`, `product`, `subProduct`, `environmentName`, `source`, `id_term` and `correlatedFindingExits`. **The API silently drops unknown keys and returns the unfiltered set.** `ac.py` refuses unknown keys and suggests close matches.
- Values are lists: `{"product":[123]}`. Boolean filters need JSON `true`; the string `"true"` is ignored.
- **Plain filter values are exact and case-sensitive** (AQL is not). Severity is title case (`Critical`), status upper case (`OPEN`), and source the exact tool name (`Wiz`, not `wiz`). A wrong case silently matches nothing; `ac.py` refuses wrong-case severity and status.
- `filterOperations` (`{"riskScore":"GREATER_THAN_EQUALS"}`-style per-key operators) accepts only `contains, notContains, startWith, endWith, equal, notEqual, include, exclude`. Use AQL for comparisons.
- An exact id list is `id_term`. `id` runs a fuzzy match.
- A top-level `aqlQuery` is ignored: AQL must go inside `filters`.
- Text filters such as `vmHostName` match by token, so `web-01` can match `web-01-staging`. For anything that drives a write, resolve to explicit ids first. The helpers do this.

## 5. Bulk changes

Use `ac.py plan findings-update --aql "…" | --ids … --status S | --severity S --note "reason"`. It:
1. Validates the AQL and counts the matches. It **refuses more than 1,000** unless the user asks for `--allow-large`. `--max N` changes at most the first N matches, which is the way to run a pilot.
2. Records each finding's prior status, severity and location in the plan, so `ac.py plan findings-revert <plan-id>` can undo the change.
3. Sends `PUT /user/findings/v2/bulk/change-basic-details` in chunks of 250 ids with `findingFilterRequest.filters.id_term`. Each chunk returns `{jobId, status:"ACCEPTED"}`.
4. Polls `GET /api/v2/jobs/{jobId}` until `COMPLETED` or `FAILED` and reports any `failedFindingIds`. A COMPLETED job can still contain failures. It then re-reads a sample of findings.

API facts:
- `notes` is required ("Note cannot be left blank") and is stored as the reason. `findingFilterRequest` is required even when ids are given.
- Each target status needs its own permission (`MARK_MITIGATED`, `MARK_ACCEPT_RISK` and so on). A key without it gets the job's failure or a 403.
- **Accept Risk**: the API allows `ACCEPTRISK` directly with `unsupressAfterDuration` (epoch **seconds**, in the future) or `slaDueDate`. `ac.py` deliberately routes risk acceptance through **exceptions** (`governance.md`), which record an owner, reason, approver and expiry. Raise this with the user rather than working around it.
- **`rulesOnFutureFindingsEnabled: true` creates a persistent rule** that applies the same change to future matching findings. Never set it unless the user explicitly wants a standing rule, and tell them how to find and remove it in the UI.
- Other fields on the same endpoint: `ownerV2:{value}`, `slaDueDate`, `category`, `multiActionTagUpdates`, `createTicket`, `developer` (ignored for scanner findings; developer comes from the scanner or SCM blame), `skipOwnerChangeEmail`.
- **Timing.** Changes are visible via `GET /user/findings/{id}` within seconds. Search results and counts can lag up to a minute.
  - Let one bulk change finish (its job COMPLETED, counts settled) before starting another on the **same findings**, and re-check the final state after chained changes.

## 6. Moving findings between subgroups

Use `ac.py plan findings-move --aql "…" | --ids … --to-subgroup SID [--env Production] --note "…"`.
- The API is the same bulk endpoint with `product`, `subProduct` and `env` as **bare integer ids**: all three or none. `env` must be the **target subgroup's** environment id ("Invalid Environment" otherwise).
- Status and severity are kept. Allow 30–60 s before judging the result.
- A later scan from the original tool mapping matched the moved finding as a duplicate and **left it where it was moved**. Still, change the tool or repository mapping too, or new findings keep landing in the old place.
- Whole subgroups move with `plan subgroup-move` instead (see `org-model.md`).

## 7. Finding tags

| Need | How |
|---|---|
| Different tags per finding, at scale | `plan raw POST /api/v2/findings/tags/bulk --body '{"entries":[{"findingId":N,"tags":["team:payments"]}]}'` |
| Add, replace or remove one key across findings | the bulk endpoint's `multiActionTagUpdates` |

Details of `/api/v2/findings/tags/bulk`:
- At most 10,000 entries per call; returns 202 with a job id.
- **Upsert by key**: a new `team:` tag replaces the finding's existing `team:` tag, and other keys stay.
- Not atomic: check the job's `failedFindingIds`.

`multiActionTagUpdates` entries are `[{action, key, values}]`:
- `ADD_UPDATE` replaces the key's values.
- `ADD` appends values.
- `REMOVE` deletes the given values, or the whole key when no values are given.

Tags are stored lowercase and need `UPDATE_FINDING_TAGS`.

## 8. Correlation

- ArmorCode's AI correlation runs nightly and groups findings that share a fix: the same CVE and component across SCA and containers, SAST↔DAST on the same vulnerability type, the same image or host across apps, and so on.
- Each finding carries `correlationMetadata[{correlationId, correlationName (= remediation group), remediationAction, context}]`. The primary finding of a group carries the tag `armorcode.primary_correlated_finding:*`.
- AQL: `isCorrelated = true`, `isUnique = true` (uncorrelated or primary), `remediationGroup LIKE '…'`. `correlationId IN (…)` works but isn't a documented AQL field.
- Raw filters: `correlatedFindingExits: [true]`, `uniqueCorrelatedFindingExits: [true]` (JSON booleans), `correlationIds: [id]`.
- Manual correlation: `plan raw POST /user/findings/correlated --body '{"findingId":N,"correlatedFindingIds":"M","note":"…","correlationName":"…"}'` (one id per call).
- "Unique" counts (`isUnique = true`) are the de-duplicated workload. Use them for "how many things do we actually need to fix".

## 9. Recipes

### Triage false positives at scale
1. Agree the rule with the user, then validate it: `ac.py findings aql-check --aql "<rule>"`.
2. Sample it: `ac.py findings list --aql "<rule>" --limit 20 --fields id,title,source,subProduct.name,filePath`. Show the sample and ask whether it looks right.
3. Pilot: `plan findings-update --aql "(<rule>) AND product = <one group id>" --status FALSEPOSITIVE --note "<reason, ticket ref>"`, or add `--max 20` to change only the first 20 matches. Apply after approval and verify.
4. Run the rest. Keep the plan id: `plan findings-revert <id>` undoes it.

### Drain a landing zone (e.g. `<DEFAULT>`) without losing anything
1. **Baseline**: `ac.py findings count --aql "subProduct = SRC"` and the same with `--by status` (AQL counts every status). Save both outputs.
2. Decide the routing with the user (by host, image, account, repo or tag) and build one AQL per target subgroup. Check that the AQLs don't overlap (each finding matches one rule) and that together they cover everything: the counts must add up to the baseline.
3. One `plan findings-move` per target subgroup. Pilot one, then do the rest.
4. **Reconcile**: re-count the source and targets after a minute. The source should drop by exactly the moved amount and the targets rise by it. Report any difference, with ids from `findings list`.
5. Point the tool mapping at the right subgroups (`integrations.md` §1) so new findings stop landing in the zone.

### "Why don't the API and UI counts match?"
Check, in order:
1. **Status set**: the UI's default view vs `status IN (…)`. Remember CONTROLLED is UI Mitigated and MITIGATED is UI Remediated.
2. **MITIGATED exclusion**: plain-filter searches leave out MITIGATED by default; AQL searches don't.
3. **Environment**: the UI may default to Production. Add `environmentName = 'Production'`.
4. **Scope**: the key's scope vs the user's UI access, and the organization. API counts include every organization the key sees (Archive too) unless you add `--org`.
5. **Freshness**: index lag of up to a minute after bulk changes and uploads.
6. **Duplicates vs unique**: correlated findings appear once in "unique" views.

### Export for BI (Power BI, Excel, a data lake)
- Summary metrics: `findings count --by product --aql "<scope>" --out metrics.json`.
- Row-level data: `findings list --aql "<scope>" --fields id,severity,status,title,product.name,subProduct.name,environment.name,source,cve,componentName,riskScore,foundOn,slaDueDate,developer --out findings.csv`.
- Schedule it outside Claude (cron or CI) with the same commands and a read-only profile.
- ArmorCode can also email scheduled reports from saved views (`governance.md`).
