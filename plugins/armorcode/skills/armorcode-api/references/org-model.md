# Org model: organizations, groups, subgroups, hierarchy, repositories

## Contents
1. Names in the UI vs the API
2. Reading the org quickly
3. How the hierarchy works
4. Groups
5. Subgroups
6. Environments
7. Archive and deletion
8. Repositories (SCM) and subgroups
9. Recipes: audit, hierarchy as code, re-parenting, sprawl cleanup, repo mapping, tiers

---

## 1. Names in the UI vs the API

| UI | API | Notes |
|---|---|---|
| Organization | business unit (`businessUnitId`, `/api/tenant/businessUnits`) | Most tenants have one, plus **Archive** once anything has been deleted |
| Group (ASPM: Application; RBVM: Asset Group) | product (`product`, `/user/product`) | Name unique per organization, 2–228 characters |
| Subgroup (ASPM: Repository/Component) | sub-product (`subProduct`, `/api/sub-product`) | Name unique within its group |
| Environment | `environmentDtos` on a subgroup | Per-subgroup records with their own ids |
| Hierarchy node | `armorcode.group:<path>` tag | Not a separate object |
| Tier | group `tier` = a RISK_TIERS id | |

Labels vary with the tenant's use case, and admins can rename them (Global Settings > Configuration > Titles). Use the user's words, and map them to the API terms yourself.

Renaming an organization is UI-only, and `GET /business-unit/` isn't supported; read organizations with `GET /api/tenant/businessUnits` (`ac.py bus`).

## 2. Reading the org quickly

| Need | Command | Endpoint |
|---|---|---|
| Organizations | `ac.py bus` | `GET /api/tenant/businessUnits` (Internal) |
| All groups, with tier, team, tags, subgroup count | `ac.py groups [--search TEXT] [--all-orgs]` (substring match on the name; `--all-orgs` includes other organizations, Archive among them) | `POST /user/product/elastic/paged`, `pageSize` ≤ 100. Ids come back as **strings**; `ac.py` converts them |
| One group, complete | `ac.py group ID [--full]` | `GET /user/product/{id}?ignoreSubProducts=true` |
| A group's subgroups | `ac.py subgroups --group ID` | `POST /api/sub-product/name-id {"productIds":[ID]}` |
| One subgroup (own vs inherited tags, env ids) | `ac.py subgroup ID` | `GET /api/sub-product/{id}` |
| **Whole hierarchy in one call** | `ac.py hierarchy`, `--lint`, `hierarchy-export` | `GET /api/sub-product/team-hierarchy`: one row per subgroup, with effective tags, group tags and tier |

Gotchas:
- The filter field is `productIds` on `/api/sub-product/name-id` but `productId` (an array) on `/api/sub-product/list`. Sending the wrong one silently returns every subgroup.
- A subgroup's GET `tags` is its **effective** list: its own tags plus everything inherited. `tagsMetaMap` splits them by source:
  - `SUB_PRODUCT`: its own tags.
  - `PRODUCT`: inherited from the group.
  - `TOOL`: from tool configurations, as `[{toolConfigId, environment, tags}]`.
  - `RUNBOOK`: added by runbooks.

## 3. How the hierarchy works

- A hierarchy node is a tag: `armorcode.group:acme/payments/checkout`. The tag splits at the first colon, and `/` separates levels. One tag holds the full path; parents don't need their own tags.
- **The whole tag is stored lowercase**, key and value. On save, ArmorCode trims the path, strips leading and trailing `/`, collapses `//`, and removes spaces around `/`. A tag with an empty value is dropped.
- Usually the tag sits on the **group**, and every subgroup inherits it. Inheritance is copied asynchronously: a subgroup's detail can show the old path for some seconds after a group changes, while `team-hierarchy` already shows the new one.
- A group can sit at several paths (several tags). A subgroup can add its own `armorcode.group` tag to appear at another path as well (cross-placement). `ac.py hierarchy --lint` lists both cases.
- No depth or character limit was found. Keep paths short, consistent and lowercase. Paths that differ only in spacing or separators (`acme/data-platform` vs `acme/data platform`) split one team's view into two. `--lint` flags them.
- **Teams and API keys follow the hierarchy.**
  - A team's access scope lists paths in `properties[].groups`. A bare path matches **that node only**. `path/.*` matches the node **and everything below it**.
  - Matching is case-sensitive against the lowercase stored tags, so write team paths in lowercase.
  - API keys scoped by hierarchy resolve at call time.
  - So moving a group to a new path changes who can see it. Check which teams and keys reference the old and new paths before re-parenting.

## 4. Groups

**Create**: `ac.py plan group-create --name … [--hierarchy path] [--tag k:v] [--tier ID --tier-tags] [--type-id ID]` sends `POST /user/product`. Only `name` is required.

**Update**: `ac.py plan group-update ID …` is a read-merge-write at apply time.
- `PUT /user/product` **replaces the object**. A sparse body wiped `tier`, `description`, `status` and `classType`.
- On groups with many populated fields, ArmorCode instead rejects a body missing more than 30% of them, with 400 "Wide range update detected".
- Either way, the safe pattern is: GET everything, change what you need, PUT everything back. The helper does exactly that, backs the object up first, and verifies afterwards.

Field formats:
- `status`: `Active` | `Suspended` | `End of life`.
- `tier`: the **id** of a tier in `GET /api/tenant-config?configType=RISK_TIERS`, which returns `[{id, name, tags:[{name, fieldValue, weight}]}]`.
  - Ids are often `"1"`/`"2"`/`"3"` but tenant-specific.
  - Sending a name (`"Tier 2"`) returns 200, but the group overview then shows N/A.
- **Tier risk tags**: when someone changes the tier in the UI, the UI swaps in that tier's tags (`business-impact:…`, `compliance:…`, `data-sensitivity:…`, `ext-facing:…`), and they drive the asset score. The API doesn't do this. Use `--tier-tags` to match the UI.
- `classType`: `Software only` | `Software & Hardware` (older values exist).
- `type`: `{"id": N}` from `GET /user/product-type`. Default types are global; custom types belong to the tenant. Look them up by name and never hard-code ids. A bare string returns 400.
- Owners: `businessOwner`, `securityOwner`, `engineeringOwner`, `supportOwner`, `complianceOwner` as `{"id": userId}`; they read back as `{id, email, displayName}`. The UI only offers members of the group's assigned team (`teamDto: {"id": teamId}`), so pick owners from that team.
- **Assign a team (`--team-id`) and owners on every group.** Dashboard widgets and reports grouped by team leave out groups without one. Use the most specific team whose access scope covers the group.
- `slaTemplateId`: the group's SLA policy (`--sla-template-id`; see `governance.md` §3).
- `artifacts: [{name, link}]`: the whole list is replaced; the helper appends and dedupes.

Bulk endpoints exist (`PATCH /v2/products/mass` **replaces** each group's tag list, up to 1000 groups; `PATCH /user/product/bulk`'s add-vs-replace semantics are unverified). Prefer the per-group helpers or `hierarchy-sync`. They're slower but safe.

## 5. Subgroups

**Create**: `ac.py plan subgroup-create --group ID --name … [--tag k:v]` sends `POST /api/sub-product {name, product:{id}}`.
- **Production** and **Staging** environments are created automatically when none are given.
- Group tags are inherited, not copied.
- The create response doesn't reliably include the new id, so the helper looks it up afterwards.

**Update**: `ac.py plan subgroup-update ID [--name] [--add-tag] [--remove-tag] [--hierarchy]` sends `PUT /api/sub-product` with `{id, name, product:{id}}` plus the other fields.
- The `tags` array replaces only the subgroup's **own** tags. ArmorCode strips any tag that equals one of the group's, so sending the effective list back is harmless.
- The other writable fields follow full-replace rules and the 30% guard. The helper sends everything back.
- Inherited tags can't be removed on the subgroup; change the group instead.

**Move to another group**: `ac.py plan subgroup-move ID… --to-group GID` sends `POST /api/sub-product/bulk/move {subProductIds, productId}`.
- The call is synchronous, and the destination must be in the same organization.
- Findings and configurations move with the subgroup. It then inherits the new group's hierarchy, tier tags and team access.

**Versions** (Internal; needs the Versions feature): `POST /api/sub-product/version {subProductId, version, cloneManualFindings:false, status:""}` creates a sibling subgroup "name (version)". It copies tags but not tool mappings or findings.

## 6. Environments

- Each subgroup has its own environment records (`environmentDtos` on its GET), each with an id. Names are title case (`Production`, `Staging`).
- Finding moves and repository mappings need the **target subgroup's** environment id. An id from another subgroup fails with "Product ID does not match Environment ID".
- Scan uploads check the environment name against the subgroup's environments. An environment can be disabled tenant-wide (Staging often is) and still accept data, so the upload helper names the environment in the plan.

## 7. Archive and deletion

- **Archive / soft delete** moves the subgroup or group into the **Archive** organization. ArmorCode creates that organization the first time something is archived.
  - Archiving a subgroup creates (or reuses) an Archive-side group with the **same name as its original parent**. That "duplicate" is expected; don't "clean it up".
  - Reads from the working organization then fail with 400 "Product Not Found", because the object is in another organization. It isn't corrupt.
  - Endpoints: `POST /user/product/archive/{id}?comment=…`, `POST /api/sub-product/archive/{id}`, `DELETE …/{id}` (soft by default).
- **Hard delete** (`?delete=true`) is permanent, and group hard deletes finish asynchronously, within seconds. `ac.py` rates these plans CRITICAL. They need `--allow-destructive` and the user's explicit approval of a permanent delete.
- Before deleting or archiving, check what depends on the object: findings, tool mappings, repository mappings, ticket mappings, runbooks, saved views and dashboards that reference its id or path.

## 8. Repositories (SCM) and subgroups

| Need | Command / endpoint |
|---|---|
| List repos and their mapping | `ac.py repos [--unmapped] [--type GITHUB] [--search]`. Endpoint: `GET /user/tools/git?page&size` (Internal); a short page means the end |
| Trigger discovery of new repos | `plan raw POST /user/tools/github/repo-sync -p repoType=GITHUB` (or GITLAB, BITBUCKET, AZURE_REPOS); otherwise it runs daily |
| Map one repo | `ac.py plan repo-map REPO --subgroup SID [--branch main] [--env Production]` |
| Map many | `ac.py plan repo-map --csv map.csv` (columns `repo,subgroup_id[,branch,environment]`; `repo` = id or exact name; example in `assets/repo-map.example.csv`) |

Details of `PUT /user/tools/git/token/{repoId}` (Internal):
- Send `repoType`. The listing calls it `repositoryType`, and omitting it has returned a bare 500.
- `environmentId` is the target subgroup's own environment id.
- Echoing the whole listing record back has also failed. The helper builds the right body and records the previous mapping in the plan.

An alternative route used for GitLab is `PUT /user/tools/git/repo {repoId, productId, subProductId, envId, envName, branchName, hostUrl}`. `branchName` is required.

GitLab specifics:
- Synced GitLab repository names look like `"<group> / <slug>"`. When matching repositories to subgroups by name, match on the URL slug (the last segment of `repoUrl`, without `.git`) rather than on `name`.
- The GitLab integration can't be limited to one GitLab group, and there is no API to remove synced repositories. To keep other repositories out, connect with a token whose user sees only the intended groups, or leave the extra repositories unmapped.

SCM sync stamps `armorcode.repo.*` tags on mapped subgroups: url, branch, topics, custom properties, CODEOWNERS entries and so on. Those tags are a convenient key for hierarchy and team automation.

**Map repos before ingesting their findings.** Developer attribution (git blame against the mapped branch) happens at ingestion time. Findings ingested before mapping show developer "Not Found".

## 9. Recipes

### Audit the hierarchy
1. Run `ac.py hierarchy --depth 3` for the shape and `ac.py hierarchy --lint` for subgroups with no path, cross-placed subgroups and near-duplicate paths.
2. Run `ac.py groups --out groups.json`. Groups with `subgroups: 0` and no findings are cleanup candidates. Check findings with `ac.py findings count --filters '{"product":[ID]}'`.
3. Report the findings as a short list with ids. Change nothing until the user picks what to fix.

### Hierarchy as code (manage the org from a file)
1. Run `ac.py hierarchy-export --out org.json`. This is the source of truth to commit to git. A small annotated example is in `assets/hierarchy.example.json`.
   - Format: `{"groups":[{"name", "hierarchy":[paths], "tier", "status", "description", "tags":[…], "subgroups":[{"name", "tags":[…]}]}]}`.
   - The ids in it are informational. Matching is by name: group names within the organization, subgroup names within their group.
2. Edit the file. Add groups and subgroups, change `hierarchy` paths, add tags. A `hierarchy` list **replaces** the group's `armorcode.group` tags. Other tags are added; use `--exact-tags` to also remove group tags missing from the file.
3. Run `ac.py plan hierarchy-sync --desired org.json`. It shows creates, updates and moves, and notes groups and subgroups present in the tenant but absent from the file. **It never deletes or archives.** `--move-misplaced` moves a subgroup found under a different group.
4. Review the plan with the user, then apply. Re-running the plan on an unchanged file reports no changes. Use that as the drift check in a scheduled job or CI.
5. If you change `tier` in the file, update that group's risk tags in the file too, or run `plan group-update --tier N --tier-tags` afterwards.

### Re-parent part of the hierarchy
1. Run `ac.py hierarchy` to find the affected groups.
2. Run `ac.py teams` and `team ID` to find teams whose scope covers the old or new path.
3. For each group, run `plan group-update ID --hierarchy new/path`. For many groups, edit the export and use `hierarchy-sync`.
4. Warn the user that team visibility, hierarchy-scoped API keys, and saved views, dashboards or runbooks filtered by path follow the new path.

### Clean up sprawl
1. Find empty or duplicate groups (audit recipe above).
2. Consolidate with `plan subgroup-move` into the surviving group. Findings move with the subgroups.
3. Archive the emptied groups with `plan raw POST /user/product/archive/ID -p comment=…`. This is HIGH risk and reversible from Archive only through support or the UI, so confirm the list explicitly.

### Map repositories by a naming rule or GitHub topic
1. Run `ac.py repos --unmapped --out unmapped.json`, and use subgroup and group names from `ac.py hierarchy-export`.
2. Build `map.csv` (`repo,subgroup_id`) from the user's rule: name prefix, org, topic or CODEOWNERS team. Show the user the rows that don't match any rule.
3. Run `ac.py plan repo-map --csv map.csv`. Review it, apply it, then trigger discovery if needed.
4. To create missing subgroups first, add them to the hierarchy file and sync.

### Set tiers and risk tags
1. Run `ac.py get /api/tenant-config -p configType=RISK_TIERS` to see the tier ids and tags.
2. Run `ac.py plan group-update ID --tier 1 --tier-tags`. It swaps out the old tier's risk tags and verifies.
