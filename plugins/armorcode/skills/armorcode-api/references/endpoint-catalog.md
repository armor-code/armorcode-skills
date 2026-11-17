# Endpoint catalog

The endpoints this skill uses, with how to call them safely. **R** reads; **W** writes and must go through `ac.py plan` → approval → `apply`.

**Stability**: *Public* means it is in ArmorCode's published API reference (checked against a tenant's `/v3/api-docs/ArmorCode`; labels last checked 2026-11-16). *Internal* means the ArmorCode web app uses it and it was verified, but it isn't in the published reference and **may change without notice**. Prefer Public endpoints, and run `ac.py spec search <term>` to see what your tenant publishes today. For anything not listed here, check the spec first.

Paths are relative to your base URL. Names in parentheses are the role permission a call needs; Account Admin keys bypass these checks.

## Contents
1. Organizations, groups, subgroups
2. Teams, users, roles, keys
3. Findings
4. Exceptions, runbooks, views, dashboards, audit, alerts
5. Tools, scans, SCM, tickets, assets, SBOM, builds


## 1. Organizations, groups, subgroups

| Method | Path | R/W | Stability | Notes |
|---|---|---|---|---|
| GET | `/api/tenant/businessUnits` | R | Internal | Organizations (business units) |
| POST | `/user/product/elastic/paged` | R | Public | Search groups; pageSize ≤ 100; ids returned as strings |
| GET | `/user/product/{id}` | R | Public | One group; ?ignoreSubProducts=true |
| GET | `/user/product/count` | R | Public | Group count |
| GET | `/user/product-type` | R | Public | Group types (look up by name) |
| GET | `/user/product/validate` | R | Public | Is a group name free? |
| POST | `/user/product` | W | Public | Create group (CREATE_PRODUCT) |
| PUT | `/user/product` | W | Public | Update group: FULL REPLACE (UPDATE_PRODUCT); use plan group-update |
| PATCH | `/v2/products/mass` | W | Public | Replace tags on ≤1000 groups (full replace per group) |
| PATCH | `/user/product/bulk` | W | Public | Bulk group update (tag add/replace semantics unverified) |
| POST | `/user/product/archive/{id}` | W | Public | Archive group (?delete=true = permanent) |
| DELETE | `/user/product/{id}` | W | Public | Delete group (soft by default; ?delete=true permanent, async) |
| POST | `/api/sub-product/name-id` | R | Public | Subgroup id/name pairs; filter productIds |
| POST | `/api/sub-product/list` | R | Public | Subgroup search; filter productId (array) |
| GET | `/api/sub-product/{id}` | R | Public | One subgroup: environmentDtos, tagsMetaMap |
| GET | `/api/sub-product/team-hierarchy` | R | Public | Every subgroup with effective tags (whole hierarchy) |
| POST | `/api/sub-product` | W | Public | Create subgroup (CREATE_SUB_PRODUCT); auto Production+Staging |
| PUT | `/api/sub-product` | W | Public | Update subgroup: own tags replaced, other fields full replace (UPDATE_SUB_PRODUCT) |
| PATCH | `/api/sub-product/mass` | W | Public | Replace own tags on ≤1000 subgroups |
| POST | `/api/sub-product/bulk/move` | W | Public | Move subgroups to another group (same organization) |
| POST | `/api/sub-product/version` | W | Internal | Create a version subgroup (Versions feature) |
| POST | `/api/sub-product/archive/{id}` | W | Public | Archive subgroup |
| DELETE | `/api/sub-product/{id}` | W | Public | Delete subgroup (soft by default) |
| DELETE | `/api/sub-product/bulk` | W | Public | Bulk permanent delete |
| GET | `/api/tenant-config` | R | Internal | ?configType=RISK_TIERS (tier ids and tags) |

## 2. Teams, users, roles, keys

| Method | Path | R/W | Stability | Notes |
|---|---|---|---|---|
| GET | `/api/team/all-teams` | R | Public | Team id/name pairs |
| GET | `/api/team/{id}` | R | Public | Team with members and scope |
| POST | `/api/team/filtered-data` | R | Public | Teams with members and scope (paged) |
| POST | `/api/team` | W | Public | Create team (CREATE_TEAM) |
| PUT | `/api/team` | W | Public | Update team settings; use with-user for membership |
| PUT | `/api/team/with-user` | W | Public | Update team incl. members (UPDATE_TEAM); replaces the member list; listed members' login is enabled |
| DELETE | `/api/team/{id}` | W | Public | Delete team (empty it first) |
| POST | `/api/v2/user/search` | R | Public | Search users; results under data.content |
| POST | `/user/add/user` | W | Public | Create user: tenantRole or teamInfo (CREATE_USER; Account Admin key) |
| PUT | `/user/update/user` | W | Public | Update user (UPDATE_USER) |
| DELETE | `/user/data/remove/{userId}` | W | Public | Remove user; their API keys stop working (DELETE_USER) |
| GET | `/user/roles` | R | Internal | Roles |
| GET | `/user/businessunit/role/permissions` | R | Internal | A role's permissions (?role=name) |
| POST | `/admin/user/role` | W | Internal | Create role; existingRole copies permissions (CREATE_ROLE) |
| POST | `/admin/user/map/role/permission` | W | Internal | Replace a role's permissions (UPDATE_ROLE) |
| POST | `/user/apikey` | W | Internal | Create API key (returns the key once) |

## 3. Findings

| Method | Path | R/W | Stability | Notes |
|---|---|---|---|---|
| POST | `/api/findings` | R | Public | Search; ?size (≤10000; 1000 tested) &afterKey; excludes MITIGATED by default |
| GET | `/user/findings/{findingId}` | R | Public | One finding |
| POST | `/user/findings/findingStats/all` | R | Public | Counts; aggField/secAggField; Reported = total |
| POST | `/user/findings/findings-filters` | R | Public | Distinct values of fields |
| POST | `/user/findings/stat/product` | R | Public | Per-group stats |
| PUT | `/user/findings/v2/bulk/change-basic-details` | W | Public | Bulk status/severity/owner/due date/move; async job (per-status permissions). ACCEPTRISK: `unsupressAfterDuration` in epoch seconds. (`PUT /api/findings/bulk` isn't supported) |
| GET | `/api/v2/jobs/{referenceId}` | R | Public | Async job status: ACCEPTED/PROCESSING/COMPLETED/FAILED |
| POST | `/api/v2/findings/tags/bulk` | W | Public | Per-finding tags; upsert by key; ≤10,000 entries; async |
| PUT | `/user/findings/findingTags` | W | Public | Same tags on many findings (UPDATE_FINDING_TAGS) |
| POST | `/user/findings/correlated` | W | Public | Manual correlation (one id per call) |
| PATCH | `/api/findings/{id}` | W | Internal | Finding attributes |
| POST | `/api/runbook/generate-aql-v2` | R | Public | Convert filters/AQL v1 to AQL v2 |

## 4. Exceptions, runbooks, views, dashboards, audit, alerts

| Method | Path | R/W | Stability | Notes |
|---|---|---|---|---|
| POST | `/api/risk-register/filter` | R | Internal | Exceptions, paged (paging in body) |
| GET | `/api/risk-register/open` | R | Public | Draft/Waiting exception id-name pairs |
| GET | `/api/risk-register/{riskRegisterId}` | R | Public | One exception |
| POST | `/api/risk-register` | W | Public | Create exception (DRAFT) |
| PUT | `/api/risk-register/{riskRegisterId}` | W | Public | Edit exception (Draft/Rejected) |
| DELETE | `/api/risk-register/{riskRegisterId}` | W | Public | Delete exception |
| POST | `/api/risk-register/{id}/submit` | W | Internal | Submit for approval |
| POST | `/api/risk-register/{id}/approve` | W | Internal | Approve (current reviewer only) |
| POST | `/api/risk-register/{id}/reject` | W | Internal | Reject |
| POST | `/api/risk-register/{id}/extend` | W | Internal | Extend end date |
| POST | `/api/risk-register/{id}/archive` | W | Internal | Archive exception |
| GET | `/api/runbook` | R | Public | Runbooks |
| GET | `/api/runbook/{id}` | R | Public | One runbook |
| POST | `/api/runbook` | W | Public | Create runbook |
| PUT | `/api/runbook/{id}` | W | Public | Update runbook |
| PUT | `/api/runbook/{id}/enable` | W | Public | Enable (applyOnExistingData runs on existing findings) |
| PUT | `/api/runbook/{id}/disable` | W | Public | Disable |
| POST | `/api/runbook/{id}/run-now` | W | Public | Run now (works even when disabled) |
| DELETE | `/api/runbook/{id}` | W | Public | Delete runbook |
| GET | `/api/runbook/{id}/jobs` | R | Internal | Runbook run history |
| GET | `/api/v2/saved-search/{filterType}` | R | Internal | Saved views (filterType = findings) |
| POST | `/api/v2/saved-search/{filterType}` | W | Internal | Create saved view (no id in response) |
| PUT | `/api/v2/saved-search/{id}` | W | Internal | Update saved view |
| PUT | `/api/savedSearch/update-sequence` | W | Internal | Pin/order/folder (send all views) |
| GET | `/user/findings/saved-search/{savedSearchId}` | R | Public | Run a saved view |
| DELETE | `/api/v2/saved-search/bulk` | W | Public | Delete ≤100 views |
| GET | `/api/custom-dashboard` | R | Internal | Dashboards |
| POST | `/api/custom-dashboard` | W | Internal | Create dashboard (widgetConfigJsonNode list) |
| PUT | `/api/custom-dashboard/{id}` | W | Internal | Update whole dashboard; system dashboards return 400 |
| GET | `/api/risk-stats/bu-trend` | R | Internal | Risk trend data behind RISK_SCORE_TREND (aggregateBy Day/Week) |
| DELETE | `/api/custom-dashboard/{id}` | W | Internal | Delete dashboard |
| POST | `/api/audit-log/search` | R | Public | Tenant audit log |
| GET | `/user/audit/log/details/page` | R | Public | Deprecated audit log |
| POST | `/api/alerts` | R | Public | Alerts |
| PUT | `/api/alerts/A-{id}` | W | Public | Update alert |
| GET | `/api/sla/template` | R | Internal | SLA policies, tenant default included; durations in ms |
| POST | `/api/sla/template` | W | Internal | Create SLA policy |
| POST | `/api/sla/template/{id}/recalculate` | W | Internal | Save & Apply: new template id; existing findings update at the next daily run |
| GET | `/api/sla/config` | R | Internal | Legacy SLA configuration (returned `[]`; don't use for policies) |
| GET | `/api/assessments` | R | Public | Pentests/assessments |
| POST | `/api/assessments` | W | Public | Create assessment (forced INPROGRESS) |
| PUT | `/api/assessments/{id}` | W | Public | Update assessment |

## 5. Tools, scans, SCM, tickets, assets, SBOM, builds

| Method | Path | R/W | Stability | Notes |
|---|---|---|---|---|
| GET | `/user/tools/generic/meta` | R | Public | Tool display names and types |
| GET | `/user/tools/generic/login_details/{tool_name}` | R | Public | Tool logins (sensitive fields may appear) |
| GET | `/user/tools/generic/configurations/{tool_name}/project` | R | Public | Projects in a tool |
| GET | `/user/tools/generic/configurations/{tool_name}/` | R | Public | List mappings (?toolType=PULL&login_id=&page=&size=) |
| POST | `/user/tools/generic/configurations/{tool_name}` | R | Public | List mappings (paged body) |
| POST | `/user/tools/generic/configurations` | W | Public | Create mappings (array; CREATE_TOOLS) |
| PUT | `/user/tools/generic/configurations` | W | Public | Update one mapping, partial (UPDATE_TOOLS) |
| DELETE | `/user/tools/generic/configurations` | W | Public | Delete mapping; deleteAllData defaults to TRUE (purge) |
| POST | `/user/tools/discovery/projects` | R | Internal | All discovered tool projects |
| POST | `/user/tools/generic/configurations/{tool_name}/upload` | W | Public | Scan upload signed URL (CREATE_TOOLS); replace semantics |
| POST | `/client/utils/scan/upload` | W | Public | Push-script upload (Report Ingestion key) |
| GET | `/api/scans` | R | Public | Scans with new/duplicate/resolved counts |
| DELETE | `/api/scans/{id}` | W | Internal | Delete scan record (findings stay) |
| POST | `/user/tools/custom/configurations` | W | Internal | Create custom tool |
| GET | `/user/tools/git` | R | Internal | SCM repositories and mappings |
| POST | `/user/tools/github/repo-sync` | W | Internal | Trigger repository discovery |
| PUT | `/user/tools/git/token/{repoId}` | W | Internal | Map repository to subgroup (send repoType) |
| PUT | `/user/tools/git/repo` | W | Internal | Alternate repository mapping |
| GET | `/user/tickets/jira/configuration/list` | R | Public | Ticket mappings (all trackers) |
| GET | `/user/tickets/jira/configuration/login/{ticketSystem}` | R | Public | Tracker logins |
| POST | `/user/tickets/jira/configuration` | W | Public | Create ticket mapping (one per group across trackers) |
| PUT | `/user/tickets/jira/configuration/{id}` | W | Public | Update ticket mapping; `"webhook": true` turns on Jira two-way sync |
| GET | `/api/v2/tickets/ticketUnifiedTemplates` | R | Internal | Ticket templates |
| POST | `/api/v2/tickets/ticketUnifiedTemplate` | W | Internal | Create template, SINGLE or MULTI (include businessUnitId) |
| PUT | `/api/v2/tickets/ticketUnifiedTemplate/{id}` | W | Internal | Update template (full body; the id is required) |
| GET | `/api/v2/tickets/unified-template-variables` | R | Internal | Template variables (?type=SINGLE\|MULTI&section=…) |
| POST | `/user/tickets/jira/bulk` | W | Internal | One ticket per finding |
| POST | `/user/tickets/jira/single` | W | Internal | One ticket for many findings (≤50; MULTI template) |
| POST | `/api/ticket` | R | Public | Search tickets (fromDate+toDate required) |
| PATCH | `/api/ticket/{id}` | W | Public | Update ticket |
| POST | `/api/v2/assets` | R | Internal | Search assets (≤100/page) |
| POST | `/api/v2/assets/upload` | W | Public | Asset CSV import: full sync per toolName |
| PUT | `/api/v2/assets/bulk` | W | Internal | Add tags to many assets (additive) |
| PUT | `/api/v2/assets/{id}/tags` | W | Internal | Replace one asset's manual tags |
| POST | `/api/components/list` | R | Public | SBOM components |
| PUT | `/api/components/{compositeId}/tags` | W | Public | Replace component user tags (EDIT_COMPONENTS) |
| POST | `/api/sbom/export` | W | Public | Export SBOM (async, emailed) |
| GET | `/api/builds` | R | Public | Release gate history |
| POST | `/client/build` | W | Internal | Evaluate a release gate (CI/CD key) |
| GET | `/v3/api-docs/ArmorCode` | R | Internal | This tenant's published OpenAPI spec |
