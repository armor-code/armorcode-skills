# Integrations: tool mappings, scan uploads, custom tools, ticketing, assets, SBOM, release gates

## Contents
1. Tool connections and project mappings
2. Uploading scan results
3. Per-tool upload notes
4. Custom tools
5. Pentests (assessments)
6. Ticketing: Jira, Azure Boards, ServiceNow
7. Assets
8. Components and SBOM
9. Release gates (CI)

---

## 1. Tool connections and project mappings

A **login** is a connection to a tool, created by the user in the UI with the tool's credentials. A **configuration** maps a project, org, host or tag in that tool to a group + subgroup + environment, and pulls on a schedule.

| Need | Endpoint |
|---|---|
| Tool names and types | `GET /user/tools/generic/meta`. The `{tool}` in paths is the **display name** (`Qualys Infrastructure`, `Github Code Scan`), URL-encoded, matched case-insensitively |
| Logins for a tool | `GET /user/tools/generic/login_details/{tool}`. **Treat the output as sensitive**: encrypted secrets are left out, but other stored fields come back. Extract only `id` and `name` |
| Projects the tool exposes | `GET /user/tools/generic/configurations/{tool}/project?login_id=N` (some tools need `&type=host`) |
| All discovered projects, mapped or not | `query /user/tools/discovery/projects -p size=100 -p page=0 --body '{}'` (Internal) |
| Existing mappings | `GET /user/tools/generic/configurations/{tool}/?toolType=PULL&login_id=N&page=0&size=100` (`POST …/configurations/{tool}` with a paged body is the equivalent search) |
| Create mappings | `plan raw POST /user/tools/generic/configurations --body @mappings.json`: a JSON **array**, 10–15 per call (`CREATE_TOOLS`) |
| Change one mapping | `plan raw PUT /user/tools/generic/configurations` with **one object** including `id`; a partial update (`UPDATE_TOOLS`) |
| Delete a mapping | `plan raw DELETE /user/tools/generic/configurations -p tool_name=X -p id=N -p deleteAllData=false` |

**⚠ Deleting a mapping defaults to `deleteAllData=true`**, which starts an asynchronous purge of that mapping's data. `ac.py` refuses the DELETE unless you set `deleteAllData` explicitly, and rates `true` as CRITICAL.

Each object in a create array needs:
- `toolType: "PULL"` (inside the object), `tool_name`, `login_id`;
- `product_name` and `sub_product_name` (names are resolved; ids alone have failed);
- `environment`, `scanType` (a comma list valid for that tool), `frequency` and `frequencyUnit`;
- plus the tool's own fields, below.

| Tool | Extra fields |
|---|---|
| Snyk | `orgId`, `orgName`, `projectId`, `projectName`, `targetId` (from discovery), `project_type:"project"` |
| Semgrep | `projectId`, `projectName` |
| Gitlab Security | `projectId`/`projectName`, comma-joined. **One config per subgroup + environment.** `scanType` from SAST, SECRET_DETECTION, DEPENDENCY_SCANNING, CONTAINER_SCANNING, DAST, IaC |
| Black Duck (`Blackduck Hub`) | `project` **and** `projectId` (both the project UUID), `projectName` |
| Qualys Infrastructure | Host: `integrationType:"Host"`, `hostId`/`hostName` comma-joined, `reportTemplateName`, `enableApiReportFetch:"true"`. Tag: `integrationType:"tag"`, `tagId`, `tagName`, `extraParams:""`. **One config per subgroup** |
| Microsoft Defender for Cloud | `subscriptionId`, `subscriptionName`, `isAllResourceGroups:true` |
| Google SCC | `organization_id:"organizations/N"`, `organization_name` |
| Veracode | `applicationId` (GUID), `applicationName`, `appId` (string). App names containing commas don't map cleanly |

After creating mappings, read them back with the GET listing. Some tools have stored a PUT's `scanType` as display names that the UI shows blank. If that happens, delete the mapping with `deleteAllData=false` and recreate it.

## 2. Uploading scan results

Use `ac.py plan scan-upload --tool "<display name>" --subgroup SID --file scan.json [--env Production] [--scan-date ISO]`. On apply it:
1. Calls `POST /user/tools/generic/configurations/{tool}/upload` with `{product, subProduct (ids), environment, fileName, scanDate, uploadTimezone}` and gets `{signedUrl, scan}` back (`CREATE_TOOLS`).
2. PUTs the file to `signedUrl` with no ArmorCode auth header. Content-Type isn't part of the signature; `ac.py` sends `text/csv` for CSV and `application/x-www-form-urlencoded` otherwise, as the web app does.
3. Polls `GET /api/scans` (newest first, matched on the unique upload name it generated) until the scan is COMPLETED or FAILED, then reports new, duplicate and resolved counts.

Rules:
- **Replace semantics.** An upload becomes the current result for that tool + group + subgroup + environment. That tool's findings there that the file doesn't refresh are set to **MITIGATED**, including everything when a file has zero findings. The plan prints how many active findings are at stake.
  - Upload one complete file per tool + subgroup + environment, and never split a scan into chunks.
  - Exceptions: VM tools (Qualys, Tenable VM incremental) resolve per host, Tenable VM only on `state: "FIXED"` rows, CSAF never resolves, and custom tools with scope tags are scoped by those tags.
- **One upload at a time per tool + subgroup.** Uploads of the same tool to the same subgroup that the server processes at the same moment don't deduplicate against each other. In one test, overlapping uploads produced about 10,000 findings where about 4,000 were expected. For several files of one tool and subgroup (successive scans, for example), send them oldest first and wait for each to reach COMPLETED before sending the next. `ac.py` does this: at apply time it waits for an earlier upload of the same tool to the same subgroup to finish, and stops without sending if it doesn't. Uploads to different subgroups or of different tools can overlap.
- **The extension picks the parser** (`.json`, `.xml`, `.zip`, `.csv` according to the tool). The content isn't sniffed. Errors read `unsupported file format: <file> for tool <tool>`.
- **`scanDate` can't be in the future.** The default is now minus 1 hour.
- **The environment must exist on the subgroup.** The plan checks it.
- **Duplicates are expected.** Re-uploading the same file gives `duplicateFindings` and changes nothing. Findings moved to another subgroup are matched as duplicates and stay where they were moved.
- Results: `ac.py scans --file NAME` for one upload, `ac.py scans --limit 100` for recent ones. `GET /api/scans` filters by `tool`, not `toolName`. A high `duplicateFindings` count on a COMPLETED scan means deduplication, not failure.
- `DELETE /api/scans/{id}` removes the scan record and file **only; findings stay**.
- Throughput: plan for about 60–70 uploads/min at most, since signed-URL creation is rate-limited per endpoint. The server processes scans in order, so large batches take minutes to index.
- **Upload keys:** this flow uses a normal API-type key with `CREATE_TOOLS`. The separate push path `POST /client/utils/scan/upload` (names instead of ids) needs a **Report Ingestion** key; other key types get 403. You rarely need it.

## 3. Per-tool upload notes

Use the scanner's own export. These are the traps:

| Tool (display name) | Format | Watch out for |
|---|---|---|
| `Checkmarx One` | `{projectName, results:[…]}` JSON | For SCA results, the CVE column comes from `similarityId`. A wrong value can't be corrected later |
| `SonarQube` | `/api/issues/search` JSON | `author` becomes the finding's developer |
| `Veracode` | Detailed Report XML 1.5 | Every numeric attribute must be filled (`sandbox_id=""` fails the scan) |
| `Gitlab Security` | Security report JSON 15.x | One file per scan type; the types don't resolve each other; an empty report resolves everything |
| `JFrog Xray` | Report `{rows:[…]}` | No CWE on this path |
| `Wiz` | GraphQL `vulnerabilityFindings.nodes` or `issues.nodes` | One report type per subgroup, because a CSPM upload resolves container findings in the same subgroup. Only Critical/High are kept by default (backend setting; ask Support) |
| `Tenable Vulnerability Management` | `.json` array | Resolves only rows with `state:"FIXED"`, per host. `plugin.cvss3_vector.raw` and `plugin.cvss3_base_score` give the CVSS v3 vector and score; the plugin output lands in the description; `plugin.family` becomes the finding tag `tenable.plugin.family` |
| `Prisma Cloud Compute` | Vulnerability CSV export (`text/csv`) | Headers are matched by exact name; the parser needs `CVE ID, Type, Severity, Package Name, Package Version, CVSS, Fix Status, Description, Repository, Tag, Clusters, Hostname, Distro, Vulnerability Link`. A `Repository` column marks rows as images (`Type` `image`), so send host rows (`Type` `host`) in a separate file without `Registry`, `Repository` or `Tag`. Deduplication includes `Hostname` but not the image: if image rows leave `Hostname` empty, the same CVE and package across many images collapses into one finding (watch `localDuplicateFindings`). Put the image reference (`registry/repo:tag`) in `Hostname` on image rows |
| `Prisma Cloud Redlock` | `{"items":[…]}` alerts JSON | Each item: `id`, `firstSeen` (epoch **ms**), `status`, `policyId`, `policy{name, severity (lowercase), policyType, recommendation}`, `resource{name, resourceType, region, account, cloudType}`. Keep alert ids stable between uploads |
| `Qualys Infrastructure` | Zip of ASSET_DATA_REPORT XML | `.json` is rejected. The same QID on different hosts can deduplicate into one finding unless Support enables host-aware dedup |
| `Rapid7 Insight` | `{"data":[…]}` | A bare array ingests nothing. Each record needs `variances[].module.name` and a unique `insight_ui_url` |
| `HackerOne` | `{"data":[…]}` | `relationships.bounties` is required, or the scan fails |
| `CycloneDX` | CycloneDX 1.5/1.6 JSON | Every PURL needs a version (see §8) |
| `Dependabot` | GraphQL `vulnerabilityAlerts.nodes` | SPDX is rejected |

**A scanner not in this table.** Don't guess the format:
1. Find the exact display name in `ac.py get /user/tools/generic/meta`, and the file type in ArmorCode's integration article for that tool. The upload takes the display name verbatim.
2. Start from a real export of the scanner, in the format that article names.
3. Prove it on a **scratch subgroup** first: upload a file with about 20 findings, wait for COMPLETED, and read the findings back (`ac.py findings list --aql "subProduct = <scratch id>" --fields id,title,severity,cve,componentName,filePath,source`). Check the count and every field you care about. Re-uploads don't refresh some stored fields, such as CVE lists, so fix the file before uploading to the real subgroup.
4. If the scanner has no native parser, use a custom tool (§4).

## 4. Custom tools

For scanners without a native parser:
- Create the tool in the UI (Security Tools > Add Custom Tool), or call `POST /user/tools/custom/configurations` (Internal) with `{name:"Custom-X", toolType:["SAST"|"DAST"|"SCA"|"SBOM"], dateFormat:"yyyy-MM-dd", fieldMapping:{SUMMARY:{customFieldName:"Title", isDedupField:true}, …}}`.
- **The name must start with `custom-`** (any case), e.g. `Custom-Acme-Fuzzer`. Valid `toolType` values are SAST, DAST, SCA and SBOM.
- Field keys include SUMMARY, DESCRIPTION, SEVERITY, UNIQUE_ID_FROM_TOOL, CVE, CWE, FILE_PATH, FILE_NAME, COMPONENT_NAME, COMPONENT_VERSION, HOST, IMAGE_NAME, REPOSITORY, TAGS, STEPS_TO_REPRODUCE, MITIGATION, IMPACT, CVSS_SCORE, CVSS_VECTOR, SCAN_DATE, STATUS, URL.
- **Upload CSV.** CSV is the supported format and the only one that applies the field mapping; JSON is parsed generically and ignores it. Required columns are whichever mapped fields are marked compulsory.
- **Map every column you care about.** Unmapped columns are appended to the description as `column: value`, and on some tool setups they have become tags. For metadata, use the mapped TAGS column with comma-separated `key:value` pairs (values can't contain commas; at most 100 tags). Upload a 2–4 row sample first and read it back before sending thousands.
- **Deduplication** joins the values of the fields marked for it. If you change those values, or the file path, between uploads, ArmorCode creates new findings and resolves the old ones. Keep the identity fields stable.
- When the mapping has both File Path and File Name, the path displays as `<File Path>/<File Name>`, so put only the directory in File Path.

## 5. Pentests (assessments)

1. `plan raw POST /api/assessments` with `{name, type:"Penetration Testing"|"Red Teaming"|"Attack Simulation"|"Threat Modelling", startDate, endDate, scope:{productId, subProductIds:[…], environmentName:"Production"}, assessors:[userId], requestedBy:userId, notes}`. It is created as INPROGRESS; mark it complete with `PUT /api/assessments/{id}` sending the full body and `status:"COMPLETE"`.
2. Upload findings with `plan scan-upload --tool "ArmorCode Pentest Management Module" --file findings.json`.
   - The file is a top-level JSON **array** of `{uniqueIdFromTool, title (required), severity, description, stepsToReproduce, impact, mitigation, cwe:"CWE-79" (string), cvssScore:8.1, url, assessment:[assessmentId]}`.
   - A wrapping object fails with "Invalid JSON submitted". Don't use the unrelated "Pentest Tools" scanner.

## 6. Ticketing: Jira, Azure Boards, ServiceNow

The user creates the tracker **login** in the UI. Then, all through the same controller (`/user/tickets/jira/…`) for every tracker:

| Need | Endpoint |
|---|---|
| Logins | `GET /user/tickets/jira/configuration/login/{JIRA\|AZURE_BOARD\|SERVICENOW…}` |
| Mappings (group → project) | `GET /user/tickets/jira/configuration/list?loginId=N` |
| Create a mapping | `plan raw POST /user/tickets/jira/configuration` (`CREATE_TICKETS`) |
| Update a mapping | `plan raw PUT /user/tickets/jira/configuration/{id}`: send the listed record minus id, audit and derived fields (`UPDATE_TOOLS`) |
| Ticket templates | `GET /api/v2/tickets/ticketUnifiedTemplates`; create with `POST /api/v2/tickets/ticketUnifiedTemplate` (Internal) **including `businessUnitId`** |
| Update a template | `plan raw PUT /api/v2/tickets/ticketUnifiedTemplate/{id}` with the full body (Internal). A PUT without the id returns "not supported", and a POST with an existing name returns "already exists" |
| Template variables | `GET /api/v2/tickets/unified-template-variables?type=SINGLE\|MULTI&section=ticketDetails` |
| Create one ticket per finding | `plan raw POST /user/tickets/jira/bulk --body '[{"findingId":N,"ticketConfigurationId":M}]'` |
| Create one ticket for many findings | `plan raw POST /user/tickets/jira/single --body '{"findingIds":[…],"ticketConfigurationId":M,"manualTicketTemplateId":T}'` |
| Read tickets (ConnectAll) | `query /api/ticket --body '{"fromDate":"2026-10-01 00:00:00","toDate":"2026-10-23 00:00:00","size":100}'`. Both dates are required, format `yyyy-MM-dd HH:mm:ss`, `toDate` not in the future |

Rules:
- **One ticket mapping per group or subgroup across all trackers.** Mapping the same group to Azure Boards fails ("Ticket Configuration already exists") until it is removed from Jira.
- **Moving groups to another project or board:** first PUT the existing mapping with its reduced `product` list, then create (or PUT) the second mapping with the moved groups. Doing it the other way round fails with the same "already exists" error.
- A mapping has: `configurationType:"PRODUCT"` with `product:[groupIds]`; `properties` mapping severity to priority; `customFields[{name, key, type, dataType, defaultVal:"${finding.x}", active}]`; and resolve/reopen statuses.
- **`resolvedStatus` and `reopenStatus` must be statuses in the Jira project's workflow.** Company-managed Kanban projects, for example, have Backlog rather than "To Do".
- Template text is Markdown without H1/H2. Start with a bold line rather than a heading.
- Jira fields that sit on a second tab of the create screen are invisible to API clients, ArmorCode included. Keep every mapped field on the first tab.
- The **ArmorCode Connect** app for Jira (Atlassian Marketplace) is recommended but not required. It adds a findings panel inside Jira issues. It is installed and configured in Jira with its own ArmorCode API key, not through this API.
- **Ticket floods:** a runbook with ticket creation can open hundreds of tickets at once. Test with a single finding first, set grouping (`subproduct` + `componentName` for dependencies, `subproduct` + `cwes` for code) and a grouping limit. See `governance.md`.

### Create a Jira mapping without the UI
Verified live: this body created a working mapping on the first try. Read the login id from `GET /user/tickets/jira/configuration/login/JIRA` and the template ids from `GET /api/v2/tickets/ticketUnifiedTemplates`.
```json
{"projectKey": "ACME", "enabled": true, "configurationType": "PRODUCT", "product": [123456], "subProductIds": [],
 "properties": {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low", "info": "Lowest"},
 "ticketSystemType": "JIRA", "issueType": "Task", "loginConfigId": 1001,
 "markResolved": true, "markReopen": true, "resolvedStatus": "Done", "reopenStatus": "Backlog",
 "labels": ["Armorcode_Associated_Finding"],
 "customFields": [{"name": "Due Date", "key": "duedate", "type": "duedate", "dataType": "duedate",
                   "defaultVal": "${finding.resolutionDueDate}", "active": true,
                   "value": null, "selectedValues": null, "mappings": null, "defaultValue": null}],
 "defaultConfiguration": false,
 "ticketUnifiedSingleTemplateId": 2001, "ticketUnifiedMultipleTemplateId": 2002,
 "describeFindingForTicket": false,
 "configMetaData": {"projectMetaData": {"id": "ACME", "name": "ACME - Acme Security"}, "ticketSystemIdMigrated": true},
 "ticketSystemIdMigrated": true}
```
1. Plan it with `plan raw POST /user/tickets/jira/configuration --body @mapping.json`.
2. **Turn on two-way status sync** (the UI's "Sync Jira Webhook" toggle). Re-list the mappings, take the new record, drop `id`, `createdAt`, `updatedAt`, `createdBy`, `updatedBy`, `lastConnected`, `lastUpdated`, `productNameId` and `subProductNameIds`, set `"webhook": true`, and `plan raw PUT /user/tickets/jira/configuration/{id}`. Verify that the read-back shows `webHookEnabled: true` and a `webHookUrl`. On Azure Boards the webhook call fails; there is no equivalent toggle.
3. Test with one finding: `POST /user/tickets/jira/bulk [{"findingId": N, "ticketConfigurationId": <mapping id>}]`. The issue appeared in Jira within about 10 seconds.

**Custom fields.** Map a Jira custom field as `{"name": "CVSS v3 Score", "key": "customfield_10050", "type": "float", "dataType": "number", "defaultVal": "${finding.cvssBaseScore}", "active": true, "value": null, "selectedValues": null, "mappings": null, "defaultValue": null}`. Jira `textfield` and `url` fields take `dataType: "string"`; `float` takes `"number"`. Keep the `duedate` entry when you add more.

| Variable | Renders as |
|---|---|
| `${finding.cvssBaseScore}`, `${finding.riskScore}` | Numbers (use a float field) |
| `${finding.cves}` | The CVE list, with brackets |
| `${finding.product.name}`, `${finding.subProduct.name}` | Group, subgroup |
| `${finding.toolName}`, `${finding.scanType}`, `${finding.hostName}`, `${finding.foundOnDate}`, `${finding.id}` | As named |
| `${finding.resolutionDueDate}` | SLA due date (Jira `duedate`) |
| `${finding.source}` | A raw object string. Don't use it |
| `${finding.owner}` | `NameIdPair(id=null…)`. Don't use it |
| `${finding.armorcodeurl}` | A link only in a SINGLE template's `ticketDetails`. Empty in custom fields, in `ticketTop` and in MULTI details: use `https://<host>/#/findings/<tenantId>/<buId>/${finding.id}` there |

### Grouped tickets (one issue for many findings)
- A **MULTI** template (`POST /api/v2/tickets/ticketUnifiedTemplate` with `type: "MULTI"`, `ticketTitle`, `ticketDetails` (rendered once per finding), `ticketBottom`, `ticketLabels`, `businessUnitId`) defines the grouped issue. Set it as a mapping's default with `ticketUnifiedMultipleTemplateId`. Useful shapes: one ticket per CVE and component, per container image rebuild, or per host patch bundle.
- `plan raw POST /user/tickets/jira/single --body '{"findingIds":[…], "ticketConfigurationId": M, "manualTicketTemplateId": T}'` (up to 50 findings) creates **one** issue with one section per finding and a "Go to Armorcode" link back to the findings. Its priority comes from the highest severity. Pick findings that share a fix: the same CVE across hosts, everything in one image, or all OS packages on one host. The ticket shows on each finding's `armorcodeTicket` after about 25 seconds.

## 7. Assets

| Need | Endpoint (Internal unless noted) |
|---|---|
| Search | `query /api/v2/assets --body '{"page":0,"size":100,"filters":{…}}'`. Unknown filter keys are ignored, so check totals. Results beyond 10,000 need narrower filters |
| Add tags to many assets | `plan raw PUT /api/v2/assets/bulk --body '{"type":"TAGS_UPDATE","ids":["…"],"tags":["k:v"],"note":""}'`. **Additive** and async. There's no bulk remove |
| Replace one asset's manual tags | `plan raw PUT /api/v2/assets/{id}/tags --body '{"tags":[…]}'`. Tool-derived tags are kept |
| Import assets from CSV | `POST /api/v2/assets/upload {toolName, assetType, delimiter:"\|", fileName}` (published), then PUT the CSV to the signed URL |

**⚠ A CSV import is a full sync for that `toolName`.** Assets of that source missing from the file are deactivated, **across all asset types**. Matching is case-sensitive. Use one import source name per feed, and always send the complete set.

To link findings to imported assets, set `assetIdFromTool` to the finding's asset id from the tool, and import assets **before** findings.

**CMDB as an asset source.** An import with `toolName: "ServiceNow CMDB"` shows its source as `ServiceNowCMDB`. The CSV `tags` column (`k:v|k:v`) flows to findings on those assets at ingest, and bulk tags added to assets later reach their findings within a few minutes. Because each import is a full sync, re-send the complete CMDB extract when you add hosts, not only the new rows.

## 8. Components and SBOM

- `query /api/components/list --body '{"page":0,"size":100}'`, `get /api/components/{id}`, and `plan raw PUT /api/components/{id}/tags` (replaces user tags; `EDIT_COMPONENTS`). The tenant needs the SBOM feature.
- Components come only from SBOM ingestion (CycloneDX or SPDX uploads, or connector SBOM pulls), not from SCA findings.
- Daily enrichment (licenses, latest versions, OpenSSF Scorecard) sends every new PURL in one batch, and **a single PURL without a version fails the whole batch**.
- Export: `plan raw POST /api/sbom/export` (async CycloneDX, emailed to the requester).

## 9. Release gates (CI)

- `POST /client/build` evaluates the release gate for a group/subgroup/environment and returns `RELEASE`, `HOLD` or `FAILED`. It needs a **CI/CD** key, not an API key. The UI's generated `slastatus.sh` (Manage > Integrations > the CI tool > Generate Script) wraps it for any CI system.
- History: `get /api/builds -p products=ID -p page=0 -p size=20`.
- Gate policy is configured in Global Settings > Release Management.
