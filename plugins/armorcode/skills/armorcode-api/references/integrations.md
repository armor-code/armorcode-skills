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
| `Tenable Vulnerability Management` | `.json` array | Resolves only rows with `state:"FIXED"`, per host |
| `Qualys Infrastructure` | Zip of ASSET_DATA_REPORT XML | `.json` is rejected. The same QID on different hosts can deduplicate into one finding unless Support enables host-aware dedup |
| `Rapid7 Insight` | `{"data":[…]}` | A bare array ingests nothing. Each record needs `variances[].module.name` and a unique `insight_ui_url` |
| `HackerOne` | `{"data":[…]}` | `relationships.bounties` is required, or the scan fails |
| `CycloneDX` | CycloneDX 1.5/1.6 JSON | Every PURL needs a version (see §8) |
| `Dependabot` | GraphQL `vulnerabilityAlerts.nodes` | SPDX is rejected |

## 4. Custom tools

For scanners without a native parser:
- Create the tool in the UI (Security Tools > Add Custom Tool; the name contains "Custom"), or call `POST /user/tools/custom/configurations` (Internal) with `{name:"Custom-X", toolType:["SAST"|"DAST"|"SCA"|"SBOM"], dateFormat:"yyyy-MM-dd", fieldMapping:{SUMMARY:{customFieldName:"Title", isDedupField:true}, …}}`.
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
| Template variables | `GET /api/v2/tickets/unified-template-variables?type=SINGLE\|MULTI&section=ticketDetails` |
| Create one ticket per finding | `plan raw POST /user/tickets/jira/bulk --body '[{"findingId":N,"ticketConfigurationId":M}]'` |
| Create one ticket for many findings | `plan raw POST /user/tickets/jira/single --body '{"findingIds":[…],"ticketConfigurationId":M,"manualTicketTemplateId":T}'` |
| Read tickets (ConnectAll) | `query /api/ticket --body '{"fromDate":"2026-10-01 00:00:00","toDate":"2026-10-23 00:00:00","size":100}'`. Both dates are required, format `yyyy-MM-dd HH:mm:ss`, `toDate` not in the future |

Rules:
- **One ticket mapping per group or subgroup across all trackers.** Mapping the same group to Azure Boards fails ("Ticket Configuration already exists") until it is removed from Jira.
- A mapping has: `configurationType:"PRODUCT"` with `product:[groupIds]`; `properties` mapping severity to priority; `customFields[{name, key, type, dataType, defaultVal:"${finding.x}", active}]`; and resolve/reopen statuses. On Jira, `"webhook": true` enables two-way status sync.
- Template text is Markdown without H1/H2. Start with a bold line rather than a heading.
  - `${finding.armorcodeurl}` renders only in single-ticket descriptions.
  - Elsewhere use `https://<host>/#/findings/<tenantId>/<buId>/${finding.id}`.
- Jira fields that sit on a second tab of the create screen are invisible to API clients, ArmorCode included.
- **Ticket floods:** a runbook with ticket creation can open hundreds of tickets at once. Test with a single finding first, set grouping (`subproduct` + `componentName` for dependencies, `subproduct` + `cwes` for code) and a grouping limit. See `governance.md`.

## 7. Assets

| Need | Endpoint (Internal unless noted) |
|---|---|
| Search | `query /api/v2/assets --body '{"page":0,"size":100,"filters":{…}}'`. Unknown filter keys are ignored, so check totals. Results beyond 10,000 need narrower filters |
| Add tags to many assets | `plan raw PUT /api/v2/assets/bulk --body '{"type":"TAGS_UPDATE","ids":["…"],"tags":["k:v"],"note":""}'`. **Additive** and async. There's no bulk remove |
| Replace one asset's manual tags | `plan raw PUT /api/v2/assets/{id}/tags --body '{"tags":[…]}'`. Tool-derived tags are kept |
| Import assets from CSV | `POST /api/v2/assets/upload {toolName, assetType, delimiter:"\|", fileName}` (published), then PUT the CSV to the signed URL |

**⚠ A CSV import is a full sync for that `toolName`.** Assets of that source missing from the file are deactivated, **across all asset types**. Matching is case-sensitive. Use one import source name per feed, and always send the complete set.

To link findings to imported assets, set `assetIdFromTool` to the finding's asset id from the tool, and import assets **before** findings.

## 8. Components and SBOM

- `query /api/components/list --body '{"page":0,"size":100}'`, `get /api/components/{id}`, and `plan raw PUT /api/components/{id}/tags` (replaces user tags; `EDIT_COMPONENTS`). The tenant needs the SBOM feature.
- Components come only from SBOM ingestion (CycloneDX or SPDX uploads, or connector SBOM pulls), not from SCA findings.
- Daily enrichment (licenses, latest versions, OpenSSF Scorecard) sends every new PURL in one batch, and **a single PURL without a version fails the whole batch**.
- Export: `plan raw POST /api/sbom/export` (async CycloneDX, emailed to the requester).

## 9. Release gates (CI)

- `POST /client/build` evaluates the release gate for a group/subgroup/environment and returns `RELEASE`, `HOLD` or `FAILED`. It needs a **CI/CD** key, not an API key. The UI's generated `slastatus.sh` (Manage > Integrations > the CI tool > Generate Script) wraps it for any CI system.
- History: `get /api/builds -p products=ID -p page=0 -p size=20`.
- Gate policy is configured in Global Settings > Release Management.
