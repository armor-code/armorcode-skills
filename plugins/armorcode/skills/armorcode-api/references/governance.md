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
- To set due dates by rule, use a `findings/updatesWithFilters` task: entries `{queryMode:"aql", aqlQueryV2, updates:{dueDays:N}}`. Every matching entry applies in order, so keep the entries mutually exclusive.

## 3. SLAs

SLA policy is best managed in the UI (Global Settings > SLA). The API surface is Internal and varies by tenant:
- SLA templates (with the SLA v2 feature): `/api/sla/template`, durations in **days** per severity or risk tier.
- Legacy configuration: `/api/sla/config` and `/api/sla/config/global`.

Read before you write, and copy units from what you read. For reporting, use findings fields: `slaDueDate`, `slaBreached`, and `triageSlaStatus`/`remediationSlaStatus`/`resolutionSlaStatus` (PASS/FAIL/N/A).

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
| Duplicate | `plan raw POST /api/custom-dashboard/ID/duplicate` |
| Import | `plan raw POST /api/custom-dashboard/import --body @dashboard.json` |
| Delete | `plan raw DELETE /api/custom-dashboard/ID` (CRITICAL) |

- **Send widgets as `widgetConfigJsonNode` (a JSON list) plus `customConfigJsonNode` (`{"totalColumns":24,"widgetHeight":24}`).** A string `widgetConfig` is ignored, which leaves a dashboard with no widgets that can then only be deleted.
- There is no full-dashboard PUT; widgets are edited individually in the UI. To change many widgets, export the dashboard JSON from the UI, edit it, and import it as a new dashboard. Retire the old one once the user confirms.
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
