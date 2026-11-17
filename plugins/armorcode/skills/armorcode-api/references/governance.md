# Governance: exceptions, runbooks, SLAs, saved views, dashboards, audit, alerts

## Contents
1. Exceptions (risk register)
2. Runbooks (automation)
3. SLAs
4. Saved views and scheduled reports
5. Custom dashboards
6. Audit logs
7. Alerts

Several endpoints here are **Internal** (used by the web app, not in the published reference); `endpoint-catalog.md` labels each one. Plan with care and read back after every change.

---

## 1. Exceptions (risk register)

An exception accepts risk for a scoped set of findings, with a reason, approvers and an end date. It is the auditable way to accept risk; `ac.py` steers accept-risk requests here instead of to a bulk status change.

**Exceptions are scoped to one group (and one environment).** Accepting risk on "CVE-X everywhere" therefore means one exception per affected group. The helper builds them all in one plan:

```bash
ac.py plan exceptions --aql "cve IN ('CVE-2024-1234') AND status IN ('OPEN','CONFIRMED','TRIAGE','IN_PROGRESS')" \
  --name "CVE-2024-1234 WAF rule" --reason "Compensating Control" --end 2026-12-31 --reviewer <userId> [--org pinned]
# ...apply, wait 1-2 minutes for findings to attach, then:
ac.py query /api/risk-register/filter --body '{"page":0,"size":100}' --out exceptions.json   # find the new ids
ac.py plan exception-action submit --ids <id> <id> --note "WAF rule 1234 blocks the exploit path"
# the reviewer (or their key) approves:
ac.py plan exception-action approve --ids <id> --note "approved"
```

- By default each exception covers **exactly today's matching findings** (its scope filter is `id IN (…)`). `--include-future` scopes by the AQL instead, so later matches join automatically.
- The AQL must contain a status condition, so closed findings aren't swept in.
- `--org` keeps the selection inside one organization. The plan warns when matched groups belong to another organization.
- Reviewers are user ids (`ac.py users --email …`), in approval order. Read the tenant's reasons from an existing exception (`ac.py get /api/risk-register/ID`) or the UI; they are tenant-configured.

| Step | Endpoint |
|---|---|
| List with status and paging | `ac.py query /api/risk-register/filter --body '{"page":0,"size":50}'` |
| Open (Draft/Waiting) id-name pairs | `ac.py get /api/risk-register/open` |
| Read one | `ac.py get /api/risk-register/ID` |
| Create (→ DRAFT) | `plan exceptions …` (or `plan raw POST /api/risk-register --body @exception.json`) |
| Submit / approve / reject / archive | `plan exception-action submit\|approve\|reject\|archive --ids … --note …` |
| Extend | `plan raw POST /api/risk-register/ID/extend` |
| Edit (Draft/Rejected only) | `plan raw PUT /api/risk-register/ID` |
| Delete | `plan raw DELETE /api/risk-register/ID` (CRITICAL) |

Raw create body, if you need fields the helper doesn't set:
```json
{"name": "Unique name", "description": "Why",
 "startDate": "2026-10-23T00:00:00Z", "endDate": "2027-01-21T00:00:00Z",
 "reasons": ["Compensating Control"],
 "scope": {"productId": 123, "subProductIds": [456], "environmentName": "Production",
           "autoAddInScopeFinding": true,
           "scopeFindingFilters": {"filters": {"aqlQueryV2": ["cve IN ('CVE-2024-1234')"]}}},
 "customWorkflow": [{"reviewerId": 789, "reviewerType": "USER", "sequence": 1}],
 "subscribersUserIds": [], "approveByDate": "2026-10-30T00:00:00Z"}
```

- **Reasons are tenant-configured** (Global Settings > Exceptions); read the existing values from an exception before creating one. `reviewerType` is `USER`, `ROLE` or `EXTERNAL_USER`. A custom workflow needs `MODIFY_APPROVERS_LIST`.
- **Keep scopes narrow.** With `autoAddInScopeFinding` and broad filters, one exception can cover hundreds of thousands of findings. Count the scope first: `ac.py findings count --aql "<same filter> AND product = <id>"`.
- In-scope findings attach just after creation, which can take a minute or two. Submitting too early fails with "no findings are associated". Wait, then submit.
- **Only the current reviewer can approve.** An API key acts as its owner, so API approval works only when the key's owner is the next reviewer. There is no admin override.
- **Approval sets the findings to ACCEPTRISK only if the tenant's exception setting for it is on.** The change rolls out over the following minutes; re-check before reporting. Otherwise the findings just carry the exception.
  - The setting "Set Status as Accept Risk which expires on the end date of Exception" (`acceptRiskOnExpiry`, Global Settings > Exceptions) also acts **on approval**: the findings go to ACCEPTRISK at once and resurface at the exception's end date. What status the exception itself gets after expiry is a separate, backend-only setting (next bullet).
- After the end date (plus a grace period), a daily job moves APPROVED exceptions to COMPLETED/EXPIRED or ARCHIVED, depending on a tenant flag. It doesn't change the findings themselves.
- Approval notification emails can trickle out for hours after bulk approvals. Warn the user before approving many at once.

## 2. Runbooks (automation)

| Need | Endpoint |
|---|---|
| List / read | `ac.py get /api/runbook`, `get /api/runbook/ID` |
| Run history | `get /api/runbook/ID/jobs` (Internal) |
| Create / update | `plan raw POST /api/runbook --body @runbook.json` / `PUT /api/runbook/ID` (HIGH) |
| Enable / disable | `plan raw PUT /api/runbook/ID/enable` or `/disable` with `--body '"note text"'` (a JSON **string**) |
| Run now | `plan raw POST /api/runbook/ID/run-now` (HIGH) |
| Convert old filters to AQL v2 | `query /api/runbook/generate-aql-v2 --body '{"aqlQuery":"…"}'` (or `filters`; never both) |

**Runbooks are the riskiest thing in the API.** They act on every matching finding, and there is no undo.
- **`applyOnExistingData: true` on an enabled FINDING runbook runs it immediately against all existing matching findings**, not just new ones.
- **`run-now` runs even if the runbook is disabled.** It returns no job id and 409 if the runbook is already running.
- **Ticket-creating runbooks can flood a tracker.** Set `groupBy` (e.g. `["subproduct","componentName"]`) and a `groupingLimit`, and test the template on one finding first (`integrations.md` §6).

Safe pattern:
1. Put the runbook's filter in AQL and run `ac.py findings aql-check` and `findings count` on it. Show the user exactly how many findings it will touch.
2. **Snapshot first**: `ac.py findings list --aql "<filter>" --all-statuses --fields id,status,severity,subProduct.id,product.id --out before.csv`. That file is the undo record, so keep it.
3. Create the runbook **disabled** with `applyOnExistingData: false`, then read it back.
4. Narrow the scope for the first run: wrap the filter as `(<filter>) AND product = <pilot id>`, run it, check the job history, and reconcile counts.
5. Widen the filter, then enable. Re-count and compare with the snapshot. If findings moved or changed unexpectedly, the snapshot plus `plan findings-update`/`findings-move` are the way back.

A FINDING runbook's skeleton, copied from a UI-built one (read an existing runbook with `get /api/runbook/ID` and follow its shape for your tenant):
```json
{"label": "Critical external findings to Jira", "description": "…", "type": "FINDING",
 "enabled": false, "applyOnExistingData": false,
 "inputs": [{"id": "newFindings", "name": "newFindings", "type": "list", "label": "New Findings", "nodeType": "trigger"}],
 "tasks": [{"name": "filteredFindings", "type": "findings/filter", "findings": "${newFindings}", "nodeType": "filter",
            "queryMode": "aql", "aqlQueryV2": "severity IN (Critical) AND tags matchAny ('ext-facing:true')"},
           {"name": "createTickets", "type": "findings/createTicket", "findings": "${filteredFindings}",
            "config": {"groupBy": ["subproduct", "componentName"], "groupingLimit": 50, "createNew": false,
                       "autoAssign": true, "markConfirmed": false}}]}
```

- Ticket creation needs no `ticketConfigurationId` when every ticket's findings sit in one subgroup: ArmorCode resolves the mapping per ticket, which is another reason to group by `subproduct` first.
- To use specific ticket templates, add `singleTicketTemplateId` and `groupTicketTemplateId` (a MULTI template, `integrations.md` §6) to the `createTicket` config.
- **`groupBy` keys are validated server-side and are lowercase**, including `team`, `product`, `subproduct`, `environment`, `scantype`, `title`, `testtype`, `filepath`, `imagename`, `vmhostname`, `remediationgroup`, `remediationaction`, `tooltitle`, `cves` and `cwes`. It is **`cves`**, not `cve`.
- To set due dates by rule, use a `findings/updatesWithFilters` task: entries `{queryMode:"aql", aqlQueryV2, updates:{dueDays:N}}`. Every matching entry applies in order, so keep the entries mutually exclusive.
- The web app sends the filter twice: `aqlQueryV2` wrapped in parentheses and `reducedAqlV2` without them, plus `"aqlModeSelected": "aql"`. Send both, as an existing runbook shows.

**Scheduled digest** (`FINDING_SCHEDULE_REPORT`, the UI's "Scheduled Finding Search"): on a schedule, filter findings and send one email. Verified live, built without a UI seed:
```json
{"label": "SLA due in 7 days - email owner and team", "description": "…",
 "type": "FINDING_SCHEDULE_REPORT", "enabled": false, "applyOnExistingData": false,
 "cron": "0 0 7 * * ?", "timeZone": "America/New_York",
 "inputs": [{"id": "findingReport", "name": "findingReport", "type": "list", "label": "Scheduled Finding Search", "nodeType": "trigger"}],
 "tasks": [{"name": "filteredFindings", "type": "findings/filter", "nodeType": "filter", "findings": "${findingReport}",
            "queryMode": "aql", "aqlModeSelected": "aql",
            "aqlQueryV2": "(status IN ('OPEN','CONFIRMED','TRIAGE','IN_PROGRESS') AND slaDueDate BETWEEN 'now()' AND 'now() + 7d')",
            "reducedAqlV2": "status IN ('OPEN','CONFIRMED','TRIAGE','IN_PROGRESS') AND slaDueDate BETWEEN 'now()' AND 'now() + 7d'"},
           {"name": "createEmail", "type": "finding/email", "nodeType": "createEmail", "findings": "${filteredFindings}",
            "config": {"owner": true, "team": true, "assignee": "", "group": false, "groupBy": []}}]}
```
- **The trigger input id is fixed per type:** `newFindings` for FINDING, `findingReport` for FINDING_SCHEDULE_REPORT. The filter task reads `"${<that id>}"`, and later tasks read `"${filteredFindings}"`.
- **`cron` is Quartz, with a seconds field first** (`sec min hour day-of-month month day-of-week`, `?` in one of the day fields): `"0 0 7 * * ?"` is 07:00 daily, `"0 30 7 ? * MON-FRI"` is 07:30 on weekdays. Always send `timeZone`.
- **`finding/email` sends one digest** of the filtered findings to their owners and/or teams (`config.owner`, `config.team`; `assignee` takes extra addresses). `finding/createEmail` is a different task that sends **one email per finding**; don't use it for a digest.
- After creating a runbook by API, open it once in the UI runbook editor to confirm it loads cleanly before enabling it.

## 3. SLAs

SLA policies live at **`/api/sla/template`** (Internal; not in the published API reference). `/api/sla/config` is the legacy configuration and returned `[]` on a current tenant, so don't read policies from there.

| Need | Endpoint |
|---|---|
| All policies, the tenant default included | `ac.py get /api/sla/template` |
| Create a policy | `plan raw POST /api/sla/template --body @sla.json` |
| Assign a policy to a group | `ac.py plan group-update GROUP_ID --sla-template-id ID` (sets the group's `slaTemplateId` by read-merge-write) |
| Apply a changed policy to existing findings | `plan raw POST /api/sla/template/{id}/recalculate --body @sla.json` (the template body) |

Copy the shape of the tenant default from the GET, without its id and audit fields:
```json
{"name": "Tier 1 - Regulated", "description": "…", "templateType": "SEVERITY",
 "severityConfigs": {"CRITICAL": {"triageDuration": 86400000, "remediationDuration": 604800000, "resolutionDuration": 1209600000},
                     "HIGH":     {"triageDuration": 172800000, "remediationDuration": 1814400000, "resolutionDuration": 2592000000},
                     "MEDIUM":   {"triageDuration": 604800000, "remediationDuration": 5184000000, "resolutionDuration": 7776000000},
                     "LOW":      {"triageDuration": 1209600000, "remediationDuration": 10368000000, "resolutionDuration": 15552000000}},
 "enabledPhases": ["TRIAGE", "REMEDIATION", "RESOLUTION"],
 "triageSlaStartOption": "FOUND_ON_DATE", "remediationSlaStartOption": "CONFIRMED_TRANSITION_DATE",
 "businessUnitId": 1234}
```
- **Durations are milliseconds** (1 day = 86,400,000; at most 999 days). A plain `7` is 7 ms, not 7 days. Convert in code and show the user the result in days.
- `templateType: "RISK_RATING"` takes `riskRatingConfigs` (keyed `veryPoorRiskScore`, `poorRiskScore`, `fairRiskScore`, `goodRiskScore`) instead of `severityConfigs`.
- **Recalculate is the UI's "Save & Apply"** ("Apply configuration to existing unresolved findings"). It isn't immediate:
  - It saves the template as a **new version with a new id**, and groups follow it. Re-read ids with `GET /api/sla/template` afterwards; never reuse a cached id.
  - The read-back shows `pendingSaveAndApply: true` until a background job runs. Existing findings get new due dates at the **next daily recalculation**; findings ingested after the change get the new policy straight away.
  - Tell the user when to expect the change, and re-count afterwards.
- A new policy is best assigned before findings are ingested, so due dates are right from the start.

For reporting, use findings fields: `slaDueDate`, `slaBreached`, and `triageSlaStatus`/`remediationSlaStatus`/`resolutionSlaStatus` (PASS/FAIL/N/A). In AQL: `slaDueDate < 'now()'` (breached) and `slaDueDate BETWEEN 'now()' AND 'now() + 7d'` (due within a week); see `aql.md`.

## 4. Saved views and scheduled reports

| Need | Endpoint |
|---|---|
| List | `ac.py get /api/v2/saved-search/findings --out views.json` (lowercase `findings`) |
| Run one | `ac.py get /user/findings/saved-search/ID -p page=0 -p size=100` (published) |
| Create | `plan raw POST /api/v2/saved-search/findings --body @view.json`. The response has no id, so re-list and match by name |
| Update | `plan raw PUT /api/v2/saved-search/ID` |
| Pin, order, folder | `plan raw PUT /api/savedSearch/update-sequence --body '{"sequence":[{"id":…,"pinned":true,"sequence":1,"folder":"…"}, …]}'`. Send **every** view's current entry, not only the one you change |
| Delete | `plan raw DELETE /api/v2/saved-search/bulk --body '[ID, …]'`. Up to 100 ids; CRITICAL; verify by re-listing |

The view's `filters` field is the Findings page's URL state:
```
filters=<urlencoded {"aqlQueryV2":["…"]}>&groupBy=<urlencoded ["cve"]>
```
`&pagination=<urlencoded {"sort":"riskScore,descend"}>` is optional.

Create body: `{"name", "filters", "exportFields":[{"field":"id","header":"ID","width":100},…], "isPublic":false, "enableScheduleReport":false, "shareTeams":[], "shareUsers":[], "storeTimeSeries":false}`.

Column `field` keys include `id, severity, title, status, riskScore, product, subProduct, environmentName, source, scanType, componentName, componentVersion, cve, slaDueDate, foundOnDate, developer, armorcodeTicket`.

Make sure a view belongs to the user, or that they mean to delete someone else's shared view, before deleting it.

## 5. Custom dashboards

| Need | Endpoint (all Internal) |
|---|---|
| List / read | `get /api/custom-dashboard`, `get /api/custom-dashboard/ID` |
| Create | `plan raw POST /api/custom-dashboard --body @dashboard.json` |
| Update in place | `plan raw PUT /api/custom-dashboard/ID --body @dashboard.json` (HIGH; back up the GET first) |
| Duplicate | `plan raw POST /api/custom-dashboard/ID/duplicate` |
| Import | `plan raw POST /api/custom-dashboard/import --body @dashboard.json` |
| Delete | `plan raw DELETE /api/custom-dashboard/ID` (CRITICAL) |

- **Send widgets as `widgetConfigJsonNode` (a JSON list) plus `customConfigJsonNode` (`{"totalColumns":24,"widgetHeight":24}`).** A string `widgetConfig` is ignored, which leaves a dashboard with no widgets that can then only be deleted.
- The web app saves a whole dashboard with `PUT /api/custom-dashboard/{id}` (Internal). Changing a live dashboard in place is risky, because a bad body can leave it unreadable. The safer route for many changes: export the dashboard JSON (GET or the UI), edit it, and import it as a new dashboard. Retire the old one once the user confirms.
- **System dashboards** (`createdBy: "system"`, such as the CISO dashboard) can't be changed by API: a PUT returned 400 "not found/accessible". Duplicate one and edit the copy.
- **Risk trend widgets** (`displayType: "RISK_SCORE_TREND"`) need `config.aggregateBy`. Unset, the UI uses `Week`, which shows nothing until a full week of daily risk snapshots exists. Send `"aggregateBy": "Day"` for a tenant or scope that is less than a week old. The trend is built from daily snapshots, so it is empty for about the first day whatever the scan history says.
- Widgets grouped by `team` read each group's assigned team (`teamDto`, `org-model.md` §4). Groups without one don't appear.
- A widget is `{x, y, w, h (24-column grid), type:"CUSTOM_WIDGET~n", config:{title, widgetType:"Findings", displayType:"Metric"|"Bar Chart"|"Donut Chart"|"Pivot Table"|"GROUPED_FINDINGS"|"Time Line"|"SLA"|…, filterType:"visual", aqlQuery, column1, column2, maxResult}}`.
  - Widget AQL follows `aql.md`: `product` is the numeric id, tags use the match operators, and the developer column is `developer`.
  - Bar charts show only the top ~5 values. For leaderboards use GROUPED_FINDINGS with `maxResult`.

## 6. Audit logs

- **Tenant audit log** (who changed what in ArmorCode): `ac.py query /api/audit-log/search -p page=0 -p size=50 --body '{"entityName":["Product"],"revisionType":["UPDATED","DELETED"]}'`.
  - Filters: `entityName` (Product, SubProduct, Finding, Runbook, User, Team…), `revisionType` (CREATED, UPDATED, DELETED, LOGGED_IN…), `user`, `startDate`/`endDate` (epoch ms).
  - Changes made through an API key are attributed to the key's owner.
  - The old `GET /user/audit/log/details/page` is deprecated.
- **Local audit log** (what this skill changed from this machine): `ac.py audit --tail 50`. It records time, profile, plan, step, endpoint and outcome. Plans and backups are in `~/.armorcode/`.

## 7. Alerts

- List: `ac.py query /api/alerts -p page=0 -p size=100 --body '{"state":["UNREAD"]}'`.
- Update: `plan raw PUT /api/alerts/A-ID --body '{"state":"READ","updateSimilar":false}'`. The path really does start with `A-`.
