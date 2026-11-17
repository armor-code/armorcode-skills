# AQL v2 for the API

AQL (ArmorCode Query Language) v2 is what the Findings page, dashboards, saved views and runbooks use. In API calls it goes inside the filters: `{"filters":{"aqlQueryV2":["<query>"]}}`. `ac.py --aql "…"` does this for you.

**Always validate before use:** run `ac.py findings aql-check --aql "<query>"`. It returns the match count or the exact 400 message the UI would show. Every example below was validated against a live tenant. Field support can change between releases, so check rather than assume.

## Syntax

- Combine conditions with `AND` and `OR`, and group them with parentheses. `NOT ( … )` is **invalid**; negate each condition instead (`!=`, `NOT IN`, `NOT LIKE`, `matchNone`, `NOT REGEXP`).
- Quote strings in single quotes. Simple words may go unquoted (`source = Wiz`, `status IN (Open, Confirmed)`).
- Operators: `=`, `!=`, `IN (…)`, `NOT IN (…)`, `LIKE '%x%'`, `NOT LIKE`, `>`, `>=`, `<`, `<=`, `BETWEEN a AND b`, `IS NULL`, `IS NOT NULL`.
- Dates are `'yyyy-MM-dd'` or `'yyyy-MM-ddTHH:mm:ssZ'`. Booleans are `= true` or `= false`.

## Field rules that trip people up

| Need | Use | Not |
|---|---|---|
| A group | `product = 123456` / `product IN (…)` (numeric id) | names (`'payments-api'`), `group` |
| A subgroup | `subProduct = 234567` (numeric id) | `'Group\|Subgroup'`, `subGroup` |
| A team | `team = 345678` (numeric id) | team name |
| An org-hierarchy subtree | `hierarchy IN ('acme/payments/*')`, which covers the node itself and everything below it (case-insensitive) | `hierarchy = 'acme/payments'`, which matches only groups tagged exactly that path, so a parent node gets 0 |
| One hierarchy node | `hierarchy = 'acme/payments/checkout'` | |
| Tags | `tags matchAny ('ext-facing:true')`, `tags matchAll ('a:1','b:2')`, `tags matchNone ('x:y')`, `tags REGEXP 'team:.*'`, `tags NOT REGEXP …`; `%` is a wildcard inside `matchAny` | `tags =`, `tags IN`, `tags LIKE` (all rejected) |
| Title text | `summary LIKE '%SQL%'` | `title` |
| Environment | `environment = 'Production'` | `environmentName` |
| Status | `status IN ('OPEN','CONFIRMED')` or `(Open, Confirmed)` | UI words such as `'Remediated'` (rejected; use `MITIGATED`) |
| Severity | `severity IN (Critical, High)` or `'CRITICAL'` | |
| Correlation | `isCorrelated = true`, `isUnique = true`, `remediationGroup LIKE '%…%'`, `correlationId IN (…)` (works, but undocumented) | |
| A group's tier | `groupTier = '1'` (the tier id) | `tier` |
| SLA due dates | `slaDueDate < 'now()'` (breached), `slaDueDate BETWEEN 'now()' AND 'now() + 7d'` (due within a week) | `dueDate`, `dueOn`, `resolutionDueDate`, `slaStatus` |
| CVSS | `baseScore >= 9`, `CVSSVector LIKE 'CVSS:3%'` (has a v3 vector) | `CVSSVector EXISTS` |
| No asset owner | `assetOwner IS NULL`. Broad: it also matches scanner-only assets that have no CMDB record | |

Group and subgroup ids come from `ac.py groups --search` and `ac.py subgroups --group ID`. Tag values are stored lowercase, so write them lowercase.

**Scope of a query.**
- **Organizations:** AQL covers every organization the key can see, the Archive organization included. There's no AQL column for organization. Add `--org ID` (or `--org pinned`) to `ac.py findings …`, which sends the plain `businessUnit` filter alongside the AQL.
- **Open:** in these examples, "open" means `status IN ('OPEN','CONFIRMED','TRIAGE','IN_PROGRESS')`. Agree the definition with the user, including whether CONTROLLED (UI Mitigated) counts.

## Useful fields

Each was validated as a column:

- **Core:** `status`, `severity`, `toolSeverity`, `summary`, `source`, `scanType` (case-sensitive: `'SAST'`), `cve`, `cwe`, `componentName`, `id`, `developer`.
- **Scope:** `product`, `subProduct`, `team`, `hierarchy`, `environment`, `tags`, `assetType` (`'HOST'`, …), `groupTier`, `assetOwner`.
- **Risk:** `riskScore`, `exploited`, `isCISAKEV`, `baseScore`, `CVSSVector`.
- **Time:** `foundOn`, `lastSeenDate`, `slaDueDate`, `findingAge` (days).
- **Workflow:** `slaBreached`, `armorcodeTicketExists`.
- **Correlation:** `isCorrelated`, `isUnique`, `remediationGroup`.

## Patterns

```
# Open critical/high, external-facing, in one subtree
status IN ('OPEN','CONFIRMED','TRIAGE','IN_PROGRESS') AND severity IN (Critical, High) AND tags matchAny ('ext-facing:true') AND hierarchy IN ('acme/payments/*')

# Known-exploited, still open, older than 30 days
isCISAKEV = true AND status IN ('OPEN','CONFIRMED','TRIAGE','IN_PROGRESS') AND findingAge > 30

# High risk, not yet ticketed
riskScore >= 800 AND armorcodeTicketExists = false AND status = Open

# One scanner's findings in one group, excluding test paths
source = 'Semgrep' AND product = 123456 AND summary NOT LIKE '%test%'

# Unique (deduplicated) work items for a team
isUnique = true AND team = 345678 AND status IN ('OPEN','CONFIRMED','TRIAGE','IN_PROGRESS')

# A specific CVE anywhere
cve IN ('CVE-2021-44228')

# CVSS 9.0+ findings in tier-1 groups
status IN ('OPEN','CONFIRMED') AND groupTier = '1' AND baseScore >= 9

# Open findings due within a week
status IN ('OPEN','CONFIRMED','TRIAGE','IN_PROGRESS') AND slaDueDate BETWEEN 'now()' AND 'now() + 7d'
```

## AQL in other places

- **Dashboards (widget `aqlQuery`)**: the same rules apply. `product` takes the numeric id, `tags` takes the match operators, and the developer column is `developer`, not `developerName`.
- **Runbooks**: filter tasks carry `aqlQueryV2`. Older runbook filters (AQL v1 or basic filters) convert with `POST /api/runbook/generate-aql-v2`, sending exactly one of `filters` or `aqlQuery`.
- **Saved views** store AQL in their URL-style `filters` string (see `governance.md`).
