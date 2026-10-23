#!/usr/bin/env python3
"""ac.py: a guarded command-line client for the ArmorCode REST API.

Part of the armorcode-api Agent Skill. Python 3.8+, standard library only.

Reads never change anything. Every change goes through plan -> review -> apply:

    ac.py plan <kind> ...                     builds a plan file and prints a dry run (nothing is sent)
    ac.py apply <plan-id> --confirm <code>    executes it, backs up what it touches, verifies, logs

Profiles marked read-only refuse to apply anything. The API token is read from an
environment variable, the macOS Keychain or a 0600 file. It is never printed or logged.

Run `ac.py --help` or `ac.py <command> --help` for usage.
"""
import argparse
import csv
import datetime as dt
import hashlib
import hmac
import json
import os
import random
import re
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

VERSION = "1.0.0"
DEFAULT_BASE_URL = "https://app.armorcode.com"
HOME = Path(os.environ.get("ARMORCODE_HOME") or (Path.home() / ".armorcode")).expanduser()
CONFIG_FILE = HOME / "profiles.json"
PLANS_DIR, BACKUPS_DIR, SPEC_DIR = HOME / "plans", HOME / "backups", HOME / "spec"
AUDIT_FILE = HOME / "audit.jsonl"

REQUEST_TIMEOUT = 120      # seconds; findings searches on multi-million-finding tenants can take ~60s
PLAN_TTL_HOURS = 24        # an older plan must be rebuilt: the tenant may have changed since the dry run
LARGE_BULK = 1000          # findings; a bulk change touching more needs --allow-large at plan AND apply time
ID_CHUNK = 250             # finding ids per bulk request (250-400 per request is a comfortable size)
FINDINGS_PAGE = 1000       # POST /api/findings page size (1000 verified; default is 10)
MAX_PRINT = 20000          # characters printed before truncating; use --out for full output
PRINT_ROW_LIMIT = 200      # findings fetched for `findings list` when printing to the screen (no --out)
PLAN_ID_RE = re.compile(r"p-\d{8}-\d{6}-[0-9a-f]{4}")
ARMORCODE_HOST_RE = re.compile(r"(^|\.)armorcode\.(com|ai|io)$")
RATE_LOW_WATERMARK = 5     # pause when X-Rate-Limit-Remaining drops to this (limits: 200/min per endpoint, 2,000/min per token)
MAX_429_RETRIES = 5        # ArmorCode's API best-practices guide: cap retries, then surface the error
BACKOFF_BASE, BACKOFF_MAX = 1.0, 20.0  # seconds; exponential backoff with jitter for 429s without a retry header
ASYNC_VERIFY_TIMEOUT = 180  # seconds to wait for async finding updates to show up on re-read

EXIT_OK, EXIT_API, EXIT_USAGE, EXIT_REFUSED, EXIT_VERIFY = 0, 1, 2, 3, 4

FINDING_STATUSES = ["OPEN", "CONFIRMED", "TRIAGE", "IN_PROGRESS", "CONTROLLED", "ACCEPTRISK",
                    "FALSEPOSITIVE", "SUPPRESSED", "MITIGATED"]
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]   # the bulk-update API rejects "High"; findings return upper case
GROUP_FIELDS_SETTABLE = {"name", "description", "status", "tier", "classType"}

# POST endpoints that only read. Anything else sent with POST/PUT/PATCH/DELETE is a change and needs a plan.
READ_ONLY_POSTS = [r"/api/findings", r"/user/findings/findingStats/all", r"/user/findings/findings-filters",
                   r"/user/findings/stat/(product|team)", r"/user/findings/under-review", r"/user/findings/details",
                   r"/user/product/elastic/paged", r"/user/product/dynamic", r"/api/product",
                   r"/api/sub-product/list", r"/api/sub-product/name-id", r"/api/sub-product/tag-library",
                   r"/api/v2/user/search", r"/api/alerts", r"/api/ticket", r"/api/ticket/findings",
                   r"/api/ticket/pagination/(ticket|comment|finding)", r"/api/team/accessible",
                   r"/api/team/filtered-data", r"/api/risk-register/assignable", r"/api/runbook/generate-aql-v2",
                   r"/user/tools/discovery/projects", r"/api/v2/assets", r"/api/components/list",
                   r"/user/tools/generic/configurations/[^/]+", r"/api/audit-log/search", r"/api/risk-register/filter"]

# Valid `filters` keys for the findings search/stats endpoints (FilterTypeEnum). Unknown keys are dropped
# silently by the API, which widens the result set, so ac.py refuses them instead.
FILTER_KEYS = set("""
    all product subProduct severity toolSeverity severityWeight cwe cve cveUsed cwes cves source status desc
    productStatus environment environmentName aeName action toolFindingStatus toolStatusOriginal
    toolSubStatusOriginal stepsToReproduce policy ruleId armorcodeTicketIds id dfId tid id_term scan
    mitigatedByScanId test developer developerName repositoryUrl repositoryName assetOwner productId title
    description url newUrl filePath armorcodeTicket armorcodeTicketUrl XRay_Path XRay_Impacted_Artifact
    Mend_Alert_Uuid newFilePath componentName componentNameHash componentVersion componentFixVersions
    cloudAccountId toolId createdAt lastUpdated lastSeenDate parserUpdatedAt securityOwner businessOwner
    engineeringOwner supportOwner complianceOwner analysisType newTitle scanType armorcodeCategory
    findingCategory toolcategory category slaBreached slaBreachedAt resolutionSlaBreached developerSlaBreached
    firstResponse issueResolved SNYK_exploitMaturity triageDueDate remediationDueDate slaDueDate findingAge
    owner armorcodeTicketExists armorcodeTicketNotExits underReview runbook proposedData proposeAction
    proposeBasicChange proposeCategory proposeDueDate proposeSeverity proposeAssignee containerImageName
    containerImageTag vmHostOs vmHostName vmHostNameSearch vmHostIP vmHostIpAddresses excludeVmHostIp team
    teamId twistLockScanType Twistlock_scanType Twistlock_originType toolTitle cluster tags keyValue
    dynamicTags tagColumnKey tagColumnValue toolProjectStatus impactScore exploitabilityScore baseScore
    findingScore armorcodeTicketSize foundOn foundOnDate publishedDate lastModifiedDate otherProperties
    commit_sha mitigation impact line projectStatusChange dfSourcefile slaDueIn slaPastDue remediationPastDue
    remediationDueIn filePathInsights armorcodeProjects aatiScore aatiScoreV2 ctiScore fixability vendor
    businessUnit exploited epssScore epssProbability isCISAKEV cvssVector cisaDueDate exploitMetaInfo
    armorcode_exploited armorcodeTicketStatus unsupressTime unsupressAfterDuration aqlQuery aqlQueryV2
    proposer ignoreSuppressed lastTriagedDate lastOpenDate lastAcceptRiskDate lastFalsePositiveDate
    lastConfirmDate lastSuppressDate subProductStatuses selectedDuration assetScore groups scanIdentifier
    scanDate scanStatus findingVersionId riskScore productTier versionFindingsCount findingCounts triggerby
    uploadedBy correlatedFindingsCount acceptRiskCount subProductTier assetType assetName assetActive assetOS
    assetOSVersions assetLocations assetCloudProviders riskRegister exceptionsStartDate exceptionsEndDate
    exceptionsReason exceptionsStatus triageSlaStatus remediationSlaStatus resolutionSlaStatus
    policyViolationId cwesStrings correlationIds assessment statusChangeReason assetIPV4 assetIPV6 assetId
    ticketOwnerNames name versionId correlatedFindingExits uniqueCorrelatedFindingExits correlationName
    remediationAction customFields proposedFrom proposedTo assessments proposeCustomFields hierarchy
    riskRating customAttribute owaspTop10_2021 cweTop25_2024 mobbFixUrl vmHostNameNormalized cvssOverallScore
    assetUniqueIdentifier triageSlaBreachTime remediationSlaBreachTime resolutionSlaBreachTime
    craExploitStatus craExploitStatusSource craNotificationStatus craUserDisclosureStatus craEarlyWarningDue
    craNotificationDue craFinalReportDue craUserDisclosureDue craClassification productCraClassification
    subProductCraClassification craEuMemberStates productCraEuMemberStates subProductCraEuMemberStates
    craProductCategory productCraProductCategory subProductCraProductCategory toolDescription timezone
    escalated escalationReason escalatedBy escalatedAt engagementName engagementType engagementStatus
    engagementOwner engagementStartDate engagementEndDate containerFindingOrigin parentBaseImageIdentifier
    layerCommand deviceType reachability toolResolvedAt euvdId euvdKev patchCompliance patchAvailable
    patchTool patchDeviceId patchAzureADDeviceId patchCatalogEntryId patchName patchKbArticle
    patchComplianceByTool patchDeviceOsVersion patchRequiredBuild patchDeviceGroup patchLastDeviceSync
    rawFindingScore findingScoreModifier
""".split())
BOOLEAN_FILTERS = {"correlatedFindingExits", "uniqueCorrelatedFindingExits", "slaBreached", "mitigated"}

SENSITIVE_KEY = re.compile(r"(password|passwd|secret|private_?key|api_?key|access_?key|credential|token)$", re.I)
NOT_SENSITIVE = {"paginationtoken", "nextpagetoken"}


# ----------------------------------------------------------------------------------------------- utilities

class Refused(Exception):
    """A guardrail stopped the operation. The message says why and what to do instead."""


class ApiError(Exception):
    def __init__(self, status, message, body=None):
        super().__init__(message)
        self.status, self.body = status, body


def now_utc():
    return dt.datetime.now(dt.timezone.utc)


def iso(ts=None):
    return (ts or now_utc()).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_home():
    for d in (HOME, PLANS_DIR, BACKUPS_DIR, SPEC_DIR):
        d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass


def write_private(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)


def redact(obj):
    """Mask credential-looking values (tool login details can contain service-account keys)."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if (isinstance(k, str) and SENSITIVE_KEY.search(k) and k.lower() not in NOT_SENSITIVE
                    and isinstance(v, str) and len(v) >= 8):
                out[k] = "***redacted***"
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


def emit(obj, out=None, max_chars=MAX_PRINT):
    """Print JSON (truncated) or save it in full to --out."""
    text = json.dumps(redact(obj), indent=2, default=str, ensure_ascii=False)
    if out:
        write_private(Path(out).expanduser(), text)
        print(f"Saved {len(text):,} characters to {out}")
        return
    if len(text) > max_chars:
        print(text[:max_chars])
        print(f"\n... truncated at {max_chars:,} of {len(text):,} characters. Re-run with --out FILE for the full result.")
    else:
        print(text)


def load_body(value):
    """--body accepts inline JSON, @path/to/file.json, or - for stdin."""
    if value is None:
        return None
    if value == "-":
        return json.load(sys.stdin)
    if value.startswith("@"):
        return json.loads(Path(value[1:]).expanduser().read_text(encoding="utf-8"))
    return json.loads(value)


def norm_tag(tag):
    """ArmorCode stores tag values lowercased; compare tags case-insensitively."""
    return str(tag).strip().lower()


def dedupe_tags(tags):
    seen, out = set(), []
    for t in tags or []:
        k = norm_tag(t)
        if k and k not in seen:
            seen.add(k)
            out.append(t)
    return out


def epoch_ms_to_iso(v):
    if isinstance(v, (int, float)) and v > 10 ** 11:
        return dt.datetime.fromtimestamp(v / 1000, dt.timezone.utc).strftime("%Y-%m-%d")
    return v


def dig(obj, dotted):
    """Read a.b.c from nested dicts; lists of dicts are mapped."""
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, list):
            cur = [c.get(part) if isinstance(c, dict) else None for c in cur]
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def unwrap(d):
    """Many endpoints wrap results as {data: ..., success: ...}; some don't."""
    if isinstance(d, dict) and "data" in d and ("success" in d or "timestamp" in d):
        return d["data"]
    return d


# ----------------------------------------------------------------------------------------------- profiles

def load_config():
    if CONFIG_FILE.exists():
        return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    return {"profiles": {}, "default": None}


def save_config(cfg):
    ensure_home()
    write_private(CONFIG_FILE, json.dumps(cfg, indent=2))


def select_profile(args):
    cfg = load_config()
    name = getattr(args, "profile", None) or os.environ.get("ARMORCODE_PROFILE") or cfg.get("default")
    if not name:
        raise Refused("No profile configured. Create one first, e.g.\n"
                      "  ac.py profile add prod --token-env ARMORCODE_TOKEN --mode read-only --default")
    prof = cfg.get("profiles", {}).get(name)
    if not prof:
        raise Refused(f"Profile '{name}' not found. Known profiles: {', '.join(cfg.get('profiles', {})) or 'none'}")
    return name, prof


def resolve_token(prof):
    if prof.get("token_env"):
        val = os.environ.get(prof["token_env"], "").strip()
        if not val:
            raise Refused(f"Environment variable {prof['token_env']} is not set or empty in this shell. Set it in "
                          "your shell profile (~/.zshenv is read by non-interactive shells) and open a new terminal.")
        return val
    if prof.get("token_keychain"):
        r = subprocess.run(["security", "find-generic-password", "-s", prof["token_keychain"], "-w"],
                           capture_output=True, text=True)
        if r.returncode != 0 or not r.stdout.strip():
            raise Refused(f"No macOS Keychain item with service '{prof['token_keychain']}'. Add it with:\n"
                          f"  security add-generic-password -s {prof['token_keychain']} -a \"$USER\" -w")
        return r.stdout.strip()
    if prof.get("token_file"):
        p = Path(prof["token_file"]).expanduser()
        if not p.exists():
            raise Refused(f"Token file {p} does not exist.")
        if p.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise Refused(f"Token file {p} is readable by other users. Run: chmod 600 {p}")
        return p.read_text(encoding="utf-8").strip()
    raise Refused("Profile has no token source (token_env, token_keychain or token_file).")


# ----------------------------------------------------------------------------------------------- HTTP client

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects with the API key attached; a redirect surfaces as an HTTP error instead."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def is_read_post(path):
    return any(re.fullmatch(p, path.split("?")[0].rstrip("/")) for p in READ_ONLY_POSTS)


class Client:
    def __init__(self, profile_name, prof):
        self.profile_name, self.prof = profile_name, prof
        self.base = prof.get("base_url", DEFAULT_BASE_URL).rstrip("/")
        if not self.base.startswith("https://"):
            raise Refused(f"Profile '{profile_name}' uses {self.base}; only https:// base URLs are allowed.")
        self._token = resolve_token(prof)
        self.rate_remaining = None
        self.allow_writes = False          # only cmd_apply turns this on, after every guard has passed
        self._opener = urllib.request.build_opener(_NoRedirect)

    @property
    def writable(self):
        return self.prof.get("mode") == "read-write"

    def _scrub(self, text):
        return text.replace(self._token, "***") if self._token else text

    def request(self, method, path, body=None, params=None, idempotent=None, timeout=REQUEST_TIMEOUT):
        """Send one request. Retries 429 always (the server did not process it) and transient
        5xx/network errors only for idempotent calls, so a write is never sent twice."""
        method = method.upper()
        if method != "GET" and not self.allow_writes and not (method == "POST" and is_read_post(path)):
            raise Refused(f"{method} {path} changes data and can only be sent by `ac.py apply` for a reviewed plan.")
        if idempotent is None:
            idempotent = method == "GET"
        url = self.base + (path if path.startswith("/") else "/" + path)
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params, doseq=True)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        transient_tries = 3 if idempotent else 1
        attempt = 0
        while True:
            attempt += 1
            if self.rate_remaining is not None and self.rate_remaining <= RATE_LOW_WATERMARK:
                time.sleep(15)
                self.rate_remaining = None
            req = urllib.request.Request(url, data=data, method=method, headers={
                "Content-Type": "application/json", "Accept": "application/json",
                "User-Agent": f"armorcode-api-skill/{VERSION}"})
            req.add_unredirected_header("Authorization", f"Bearer {self._token}")
            try:
                with self._opener.open(req, timeout=timeout) as resp:
                    self._note_rate(resp.headers)
                    raw = resp.read()
                    status = resp.status
            except urllib.error.HTTPError as e:
                self._note_rate(e.headers)
                raw = e.read()
                status = e.code
                if status == 429 and attempt <= MAX_429_RETRIES:
                    # Header present: the request quota was hit, wait exactly that long.
                    # Header absent: the per-token concurrency limit was hit, back off with jitter.
                    wait = e.headers.get("X-Rate-Limit-Retry-After-Seconds")
                    if wait:
                        time.sleep(float(wait))
                    else:
                        exp = min(BACKOFF_MAX, BACKOFF_BASE * 2 ** (attempt - 1))
                        time.sleep(exp + random.uniform(0, exp / 4))
                    continue
                if status >= 500 and attempt < transient_tries:
                    time.sleep(2 ** attempt)
                    continue
                if 300 <= status < 400:
                    raise ApiError(status, f"{method} {path} -> HTTP {status} redirect to {e.headers.get('Location')} "
                                           "(not followed; check the profile's base URL)")
                text = self._scrub(raw.decode("utf-8", "replace"))
                try:
                    parsed = json.loads(text)
                    msg = parsed.get("message") or parsed.get("detail") or parsed.get("error") or text
                except (ValueError, AttributeError):
                    parsed, msg = text, text
                raise ApiError(status, f"{method} {path} -> HTTP {status}: {str(msg)[:500]}", parsed)
            except (urllib.error.URLError, TimeoutError, ConnectionError, socket.timeout) as e:
                if attempt < transient_tries:
                    time.sleep(2 ** attempt)
                    continue
                hint = "" if idempotent else " The request may or may not have been processed; re-read before retrying."
                raise ApiError(0, f"{method} {path} -> network error: {self._scrub(str(e))}.{hint}")
            text = raw.decode("utf-8", "replace")
            if not text:
                return None
            try:
                return json.loads(text)
            except ValueError:
                return text

    def _note_rate(self, headers):
        try:
            v = headers.get("X-Rate-Limit-Remaining") if headers else None
            self.rate_remaining = int(v) if v is not None else self.rate_remaining
        except (TypeError, ValueError):
            pass

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def read_post(self, path, body, **kw):
        return self.request("POST", path, body=body, idempotent=True, **kw)


# ----------------------------------------------------------------------------------------------- tenant helpers

def business_units(c):
    return unwrap(c.get("/api/tenant/businessUnits")) or []


def working_bu(c):
    """The profile's business unit if pinned, else the first non-Archive BU."""
    if c.prof.get("business_unit_id"):
        return int(c.prof["business_unit_id"])
    bus = [b for b in business_units(c) if str(b.get("name", "")).lower() != "archive"]
    if len(bus) > 1:
        print(f"note: {len(bus)} business units visible; using '{bus[0]['name']}' ({bus[0]['id']}). Pin one with "
              f"`ac.py profile add {c.profile_name} ... --business-unit ID`.", file=sys.stderr)
    return bus[0]["id"] if bus else None


def all_groups(c, bu=None, search=None):
    out, page = [], 0
    while True:
        body = {"pageNumber": page, "pageSize": 100}      # 100 is the endpoint's maximum page size
        if search:
            body["search"] = search
        d = c.read_post("/user/product/elastic/paged", body)
        rows = d.get("content") or []
        for g in rows:
            g["id"] = int(g["id"])        # this endpoint returns ids as strings; everything else uses integers
        out += [g for g in rows if bu is None or g.get("businessUnitId") is None
                or str(g.get("businessUnitId")) == str(bu)]
        if d.get("last", True) or not rows or page + 1 >= (d.get("totalPages") or 0):
            return out
        page += 1


def get_group(c, gid):
    return unwrap(c.get(f"/user/product/{int(gid)}", params={"ignoreSubProducts": "true"}))


def get_subgroup(c, sid):
    return unwrap(c.get(f"/api/sub-product/{int(sid)}"))


def subgroups_of(c, gid):
    return unwrap(c.read_post("/api/sub-product/name-id", {"productIds": [int(gid)]})) or []


def hierarchy_rows(c):
    """One row per subgroup with effective tags (own + inherited) and its group's tags and tier."""
    return c.get("/api/sub-product/team-hierarchy") or []


def find_group_by_name(c, name, bu=None):
    hits = [g for g in all_groups(c, bu, search=name) if str(g.get("name", "")).strip().lower() == name.strip().lower()]
    return hits[0] if hits else None


def env_id_for(sub, env_name="Production"):
    for e in sub.get("environmentDtos") or []:
        if str(e.get("name", "")).lower() == env_name.lower():
            return e.get("id")
    return None


def own_subgroup_tags(sub):
    meta = sub.get("tagsMetaMap") or {}
    if "SUB_PRODUCT" in meta:
        return [t.get("tag") if isinstance(t, dict) else t for t in meta.get("SUB_PRODUCT") or []]
    other = set()
    for src in ("PRODUCT", "TOOL", "RUNBOOK"):
        for t in meta.get(src) or []:
            if isinstance(t, dict) and isinstance(t.get("tags"), list):
                other |= {norm_tag(x) for x in t["tags"]}
            else:
                other.add(norm_tag(t.get("tag") if isinstance(t, dict) else t))
    return [t for t in sub.get("tags") or [] if norm_tag(t) not in other
            and not norm_tag(t).startswith("armorcode.repo.")]


def risk_tier_tags(c, tier_id):
    tiers = unwrap(c.get("/api/tenant-config", params={"configType": "RISK_TIERS"})) or []
    for t in tiers:
        if str(t.get("id")) == str(tier_id):
            return [f"{x['name']}:{x['fieldValue']}" for x in t.get("tags") or []], tiers
    raise Refused(f"Tier id {tier_id} not found in RISK_TIERS (ids: {[t.get('id') for t in tiers]}).")


def stats(c, filters):
    d = c.read_post("/user/findings/findingStats/all", {"filters": filters})
    return (d or {}).get("stats") or {}


def reported_count(c, filters):
    return ((stats(c, filters).get("Reported") or {}).get("count")) or 0


def check_filters(f):
    """Refuse filter keys the API would silently ignore, and string booleans it would silently ignore too."""
    import difflib
    for k, v in (f or {}).items():
        base = k.split(".", 1)[0]
        if k not in FILTER_KEYS and base not in FILTER_KEYS:
            close = difflib.get_close_matches(k, FILTER_KEYS, n=3)
            raise Refused(f"'{k}' is not a findings filter key; the API would ignore it and return unfiltered "
                          f"results." + (f" Did you mean {close}?" if close else "") + " Or use --aql.")
        if not isinstance(v, list):
            raise Refused(f"filter '{k}' must be a JSON list, e.g. {{\"{k}\": [{json.dumps(v)}]}}")
        if base in BOOLEAN_FILTERS and any(isinstance(x, str) for x in v):
            raise Refused(f"filter '{k}' needs JSON booleans ([true]), not strings; strings are silently ignored.")
        # Plain filter values are exact and case-sensitive (unlike AQL): a wrong case silently matches nothing.
        if k == "severity" and any(x not in ("Critical", "High", "Medium", "Low", "Info") for x in v):
            raise Refused(f"severity filter values are title case: Critical, High, Medium, Low, Info (got {v}).")
        if k == "status" and any(x not in FINDING_STATUSES for x in v):
            raise Refused(f"status filter values are upper case: {', '.join(FINDING_STATUSES)} (got {v}).")
    return f


def build_filters(aql=None, filters_json=None):
    f = dict(load_body(filters_json) or {}) if filters_json else {}
    if aql:
        f["aqlQueryV2"] = [aql]
    return check_filters(f)


def iter_findings(c, filters, all_statuses=False, limit=None, size=FINDINGS_PAGE):
    """Cursor through POST /api/findings. Stops on afterKey -1/None, an empty page, a stalled cursor or limit.
    An AQL query returns every status unless it restricts status. Plain filters leave out MITIGATED (UI:
    Remediated) unless ignoreMitigated is false, which all_statuses sends."""
    body = {"filters": dict(filters)}
    if all_statuses:
        body["ignoreMitigated"] = False
    after, seen_keys, n = None, set(), 0
    while True:
        params = {"size": size}
        if after not in (None, -1, "-1"):
            params["afterKey"] = after
        d = unwrap(c.read_post("/api/findings", body, params=params)) or {}
        rows = d.get("findings") or []
        for r in rows:
            yield r
            n += 1
            if limit and n >= limit:
                return
        nxt = d.get("afterKey")
        if not rows or nxt in (None, -1, "-1") or nxt in seen_keys:
            return
        seen_keys.add(nxt)
        after = nxt


# ----------------------------------------------------------------------------------------------- plans

RISK_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def classify_request(method, path, params=None):
    """Risk of a raw request. CRITICAL needs --allow-destructive at apply time."""
    p = path.lower()
    q = json.dumps(params or {}).lower()
    if method == "DELETE" or "delete=true" in p or '"delete": "true"' in q or '"delete": true' in q:
        return "CRITICAL", "deletes data (hard deletes cannot be undone)"
    if "/archive" in p:
        return "HIGH", "archives an object (it moves to the Archive organization)"
    if re.search(r"/runbook/\d+/(run-now|enable)|/runbook$", p):
        return "HIGH", "a runbook can act on many findings and open tickets at once"
    if "/findings" in p and ("bulk" in p or "change-basic-details" in p):
        return "HIGH", "changes findings in bulk"
    if method == "PUT" and re.search(r"^/(user/product|api/sub-product|api/team)/?$", p):
        return "HIGH", "full-object PUT: omitted fields are wiped (prefer `plan group-update`/`subgroup-update`)"
    if re.search(r"^/(api/team|api/v2/user|user/add|user/update|user/data/remove|user/apikey|admin/)", p):
        return "HIGH", "changes access control (users, teams, roles or keys)"
    if "/upload" in p:
        return "HIGH", "uploads replace a tool's findings for a subgroup + environment"
    medium = [("POST", r"/user/product"), ("POST", r"/api/sub-product"), ("POST", r"/api/v2/saved-search/findings"),
              ("PUT", r"/api/v2/saved-search/\d+"), ("PUT", r"/api/savedsearch/update-sequence"),
              ("POST", r"/api/custom-dashboard"), ("POST", r"/api/custom-dashboard/\d+/duplicate"),
              ("POST", r"/api/custom-dashboard/import"), ("POST", r"/api/assessments"),
              ("PUT", r"/api/assessments/\d+"), ("POST", r"/api/v2/tickets/ticketunifiedtemplate"),
              ("POST", r"/user/tools/github/repo-sync"), ("POST", r"/user/tools/custom/configurations"),
              ("POST", r"/api/risk-register/\d+/submit"), ("PATCH", r"/api/scans/\d+/tags")]
    if any(m == method and re.fullmatch(rx, p.split("?")[0].rstrip("/")) for m, rx in medium):
        return "MEDIUM", "creates or updates configuration"
    return "HIGH", "changes data (not on the low-risk list; review the body carefully)"


def max_risk(*levels):
    return max(levels, key=RISK_ORDER.index)


def plan_key():
    """Per-machine secret that signs plans, so a plan edited after review no longer matches its code."""
    ensure_home()
    kp = HOME / ".plan-key"
    if not kp.exists():
        write_private(kp, os.urandom(32).hex())
    return bytes.fromhex(kp.read_text().strip())


PLAN_UNSIGNED = {"hash", "results", "applied_at", "progress"}


def plan_hash(plan):
    core = {k: v for k, v in plan.items() if k not in PLAN_UNSIGNED}
    return hmac.new(plan_key(), json.dumps(core, sort_keys=True, default=str).encode(), hashlib.sha256).hexdigest()


def new_plan(c, title, steps, risk, reasons, warnings=None, preview=None, flags=None):
    ensure_home()
    stamp = now_utc().strftime("%Y%m%d-%H%M%S")
    plan = {"version": 1, "id": f"p-{stamp}-{os.urandom(2).hex()}", "created": iso(), "tool_version": VERSION,
            "profile": c.profile_name, "base_url": c.base, "mode_at_plan": c.prof.get("mode"),
            "label": c.prof.get("label", ""), "title": title, "risk": risk, "reasons": reasons,
            "warnings": warnings or [], "preview": preview or [], "flags": flags or {}, "steps": steps,
            "results": []}
    plan["hash"] = plan_hash(plan)
    write_private(PLANS_DIR / f"{plan['id']}.json", json.dumps(plan, indent=2, default=str))
    return plan


def load_plan(plan_id):
    if not PLAN_ID_RE.fullmatch(plan_id or ""):
        raise Refused(f"'{plan_id}' is not a plan id (expected p-YYYYMMDD-HHMMSS-xxxx).")
    p = PLANS_DIR / f"{plan_id}.json"
    if not p.exists():
        raise Refused(f"Plan {plan_id} not found in {PLANS_DIR}.")
    return json.loads(p.read_text(encoding="utf-8")), p


def render_plan(plan, max_steps=40):
    mode = plan.get("mode_at_plan") or "?"
    label = f" · {plan['label']}" if plan.get("label") else ""
    print(f"DRY RUN: nothing has been changed.\n")
    print(f"Plan      {plan['id']}")
    print(f"Tenant    {plan['base_url']}  [profile {plan['profile']}{label} · {mode}]")
    print(f"Change    {plan['title']}")
    print(f"Risk      {plan['risk']}: " + "; ".join(dict.fromkeys(plan.get("reasons") or [])))
    for line in plan.get("preview") or []:
        print(f"          {line}")
    steps = plan["steps"]
    print(f"Steps     {len(steps)}")
    for i, s in enumerate(steps[:max_steps], 1):
        print(f"  {i:>3}. {s.get('summary') or s.get('kind')}")
        for d in (s.get("diff") or [])[:12]:
            print(f"         {d}")
    if len(steps) > max_steps:
        print(f"  ... and {len(steps) - max_steps} more steps (full list in {PLANS_DIR / (plan['id'] + '.json')})")
    for w in plan.get("warnings") or []:
        print(f"WARNING   {w}")
    if plan.get("mode_at_plan") != "read-write":
        print("WARNING   This profile is read-only, so `apply` will be refused. Applying needs a read-write profile "
              "for this tenant (only if the user asks for one); rebuild the plan with --profile NAME.")
    flags = []
    if plan["risk"] == "CRITICAL":
        flags.append("--allow-destructive")
    if (plan.get("flags") or {}).get("allow_large"):
        flags.append("--allow-large")
    kinds = {s.get("kind") for s in steps}
    if kinds & {"merge", "restore"} or any(s.get("backup_get") for s in steps):
        print(f"\nBackups   each object is re-read and saved to {BACKUPS_DIR} just before it is changed")
    elif "findings-bulk" in kinds and any(s.get("prior") for s in steps):
        print(f"\nBackups   prior status/severity/location of every finding is stored in this plan file "
              f"(undo: ac.py plan findings-revert {plan['id']})")
    elif "findings-bulk" in kinds:
        print("\nBackups   this plan is itself a revert; the original plan file holds the earlier values")
    elif "upload" in kinds:
        print("\nBackups   none possible: an upload's effect is undone by uploading the previous file again")
    elif all(s.get("kind") == "request" and s.get("prior") for s in steps):
        print("\nBackups   the previous value of everything changed is stored in this plan file")
    elif all(s.get("method") == "POST" or s.get("kind") == "create-subgroup" for s in steps):
        print("\nBackups   not needed: this only creates new objects")
    else:
        print("\nBackups   none (no readable target). Save the current state first if you may need to roll back.")
    print(f"Apply     ac.py apply {plan['id']} --confirm {plan['hash'][:6]}" + (" " + " ".join(flags) if flags else ""))
    print("          Only run this after the user has reviewed this plan and explicitly approved it.")


# ----------------------------------------------------------------------------------------------- backups / audit

def backup(c, resource, rid, obj):
    ensure_home()
    path = BACKUPS_DIR / f"{now_utc().strftime('%Y%m%d-%H%M%S')}_{resource}_{rid}.json"
    write_private(path, json.dumps({"resource": resource, "id": rid, "base_url": c.base, "profile": c.profile_name,
                                    "taken_at": iso(), "object": obj}, indent=2, default=str))
    return path


def audit(c, plan, step_no, step, status, ok, detail=""):
    ensure_home()
    entry = {"ts": iso(), "profile": c.profile_name, "base_url": c.base, "plan": plan["id"], "title": plan["title"],
             "step": step_no, "kind": step.get("kind"), "method": step.get("method"), "path": step.get("path"),
             "status": status, "ok": ok, "detail": str(detail)[:500]}
    with open(AUDIT_FILE, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")
    try:
        os.chmod(AUDIT_FILE, 0o600)
    except OSError:
        pass


# ----------------------------------------------------------------------------------------------- merge logic

def merge_tags(current, add=None, remove=None, replace_prefix=None, replace_with=None):
    """Return the new tag list. replace_prefix (e.g. 'armorcode.group:') swaps all tags with that prefix."""
    tags = list(current or [])
    if replace_prefix is not None:
        tags = [t for t in tags if not norm_tag(t).startswith(replace_prefix.lower())] + list(replace_with or [])
    drop = {norm_tag(t) for t in remove or []}
    tags = [t for t in tags if norm_tag(t) not in drop]
    have = {norm_tag(t) for t in tags}
    tags += [t for t in add or [] if norm_tag(t) not in have]
    return dedupe_tags(tags)


def tag_diff(before, after):
    b, a = {norm_tag(t) for t in before or []}, {norm_tag(t) for t in after or []}
    return ([f"tags  + {t}" for t in after if norm_tag(t) not in b] +
            [f"tags  - {t}" for t in before if norm_tag(t) not in a])


def prepare_group_body(g):
    body = {k: v for k, v in g.items() if k not in ("subProductJpaDtos", "dependentSubProductJpaDtos",
                                                     "riskyFindingDto", "unusedRecommendedTools")}
    return body


def prepare_subgroup_body(s):
    body = {k: v for k, v in s.items() if k not in ("tagsMetaMap", "riskyFinding", "unusedRecommendedTools", "riskTrend")}
    prod = s.get("product")
    body["product"] = {"id": prod.get("id")} if isinstance(prod, dict) else {"id": prod}
    body["tags"] = own_subgroup_tags(s)      # send only the subgroup's own tags; group tags stay inherited
    return body


def apply_group_patch(g, patch):
    out = dict(g)
    for k, v in (patch.get("set") or {}).items():
        out[k] = v
    if patch.get("type_id") is not None:
        out["type"] = {"id": int(patch["type_id"])}
    if patch.get("team_id") is not None:
        out["teamDto"] = {"id": int(patch["team_id"])}
    for slot, uid in (patch.get("owners") or {}).items():
        out[slot] = {"id": int(uid)}
    if patch.get("artifacts_add"):
        arts = list(out.get("artifacts") or [])
        have = {(a.get("name"), a.get("link")) for a in arts}
        arts += [a for a in patch["artifacts_add"] if (a["name"], a["link"]) not in have]
        out["artifacts"] = arts
    out["tags"] = merge_tags(out.get("tags"), patch.get("add_tags"), patch.get("remove_tags"),
                             patch.get("replace_prefix"), patch.get("replace_with"))
    return out


def apply_subgroup_patch(s, patch):
    body = prepare_subgroup_body(s)
    for k, v in (patch.get("set") or {}).items():
        body[k] = v
    body["tags"] = merge_tags(body["tags"], patch.get("add_tags"), patch.get("remove_tags"),
                              patch.get("replace_prefix"), patch.get("replace_with"))
    return body


def group_checks(patch, final_tags):
    checks = [{"field": k, "op": "eq", "value": v} for k, v in (patch.get("set") or {}).items()]
    checks += [{"field": f"{slot}.id", "op": "eq", "value": uid} for slot, uid in (patch.get("owners") or {}).items()]
    if patch.get("team_id") is not None:
        checks.append({"field": "teamDto.id", "op": "eq", "value": patch["team_id"]})
    if patch.get("type_id") is not None:
        checks.append({"field": "type.id", "op": "eq", "value": patch["type_id"]})
    adds = [t for t in final_tags if norm_tag(t) in {norm_tag(x) for x in (patch.get("add_tags") or []) +
                                                      (patch.get("replace_with") or [])}]
    if adds:
        checks.append({"field": "tags", "op": "has_tags", "value": adds})
    if patch.get("remove_tags"):
        checks.append({"field": "tags", "op": "lacks_tags", "value": patch["remove_tags"]})
    checks.append({"field": "tags", "op": "no_duplicate_tags"})
    return checks


def run_checks(obj, checks):
    failures = []
    for ch in checks:
        val = dig(obj, ch["field"])
        op = ch["op"]
        if op == "eq" and str(val) != str(ch["value"]):
            failures.append(f"{ch['field']} is {val!r}, expected {ch['value']!r}")
        elif op == "has_tags":
            have = {norm_tag(t) for t in val or []}
            miss = [t for t in ch["value"] if norm_tag(t) not in have]
            if miss:
                failures.append(f"missing tags {miss}")
        elif op == "lacks_tags":
            have = {norm_tag(t) for t in val or []}
            extra = [t for t in ch["value"] if norm_tag(t) in have]
            if extra:
                failures.append(f"tags still present {extra}")
        elif op == "no_duplicate_tags":
            norm = [norm_tag(t) for t in val or []]
            if len(norm) != len(set(norm)):
                failures.append("duplicate tags present")
    return failures


# ----------------------------------------------------------------------------------------------- step executors

def exec_request(c, step):
    if step.get("backup_get"):
        try:
            snap = unwrap(c.get(step["backup_get"]))
        except ApiError as e:
            return False, (f"could not snapshot {step['backup_get']} before the change ({e}). Nothing was sent. "
                           "Re-plan with --no-backup only if the user accepts changing it without a backup."), None
        bpath = backup(c, "raw", re.sub(r"\W+", "_", step["backup_get"]).strip("_"), snap)
        print(f"        backup {bpath}", file=sys.stderr)
    resp = c.request(step["method"], step["path"], body=step.get("body"), params=step.get("params"), idempotent=False)
    detail = ""
    if step.get("verify_gone"):
        deadline = time.time() + 60    # some deletes (groups) complete asynchronously within seconds
        while True:
            time.sleep(5)
            try:
                obj = unwrap(c.get(step["verify_gone"]))
            except ApiError:
                break                  # 400/404 on re-read = gone
            if not (isinstance(obj, dict) and obj.get("id")) or obj.get("deleted") or obj.get("isDeleted"):
                break
            if time.time() > deadline:
                return False, ("DELETE returned success but the object still exists after 60 s. Some objects must be "
                               "emptied first (e.g. a team's members). Re-read before retrying."), resp
        detail = "verified gone"
    v = step.get("verify")
    if v:
        time.sleep(v.get("wait", 0))
        obj = unwrap(c.get(v["get"]))
        fails = run_checks(obj, v.get("checks") or [])
        if fails:
            return False, "verify failed: " + "; ".join(fails), resp
        detail = "verified" if v.get("checks") else f"re-read {v['get']} OK (no field checks)"
    return True, detail, resp


def exec_merge(c, step):
    res, rid, patch = step["resource"], step["id"], step["patch"]
    if res == "group":
        cur = get_group(c, rid)
        bpath = backup(c, "group", rid, cur)
        # Change tier/metadata and tags in separate writes: co-sending tier with tier tags has duplicated tags.
        phases = []
        meta_patch = {k: patch[k] for k in ("set", "type_id", "team_id", "owners", "artifacts_add") if patch.get(k)}
        tag_patch = {k: patch[k] for k in ("add_tags", "remove_tags", "replace_prefix", "replace_with") if k in patch}
        if meta_patch:
            phases.append(meta_patch)
        if tag_patch:
            phases.append(tag_patch)
        for ph in phases:
            fresh = get_group(c, rid)
            body = prepare_group_body(apply_group_patch(fresh, ph))
            if body == prepare_group_body(fresh):
                continue
            c.request("PUT", "/user/product", body=body, idempotent=False)
        after = get_group(c, rid)
        norm = [norm_tag(t) for t in after.get("tags") or []]
        if len(norm) != len(set(norm)):            # the server occasionally appends duplicates; collapse them
            fixed = dict(prepare_group_body(after))
            fixed["tags"] = dedupe_tags(after.get("tags"))
            c.request("PUT", "/user/product", body=fixed, idempotent=False)
            after = get_group(c, rid)
        fails = run_checks(after, group_checks(patch, apply_group_patch(cur, patch)["tags"]))
        return (not fails), (f"backup {bpath}" + ("" if not fails else "; verify failed: " + "; ".join(fails))), after
    if res == "subgroup":
        cur = get_subgroup(c, rid)
        bpath = backup(c, "subgroup", rid, cur)
        body = apply_subgroup_patch(cur, patch)
        if body == prepare_subgroup_body(cur):
            return True, f"already in the desired state (backup {bpath})", cur
        c.request("PUT", "/api/sub-product", body=body, idempotent=False)
        after = get_subgroup(c, rid)
        checks = [{"field": k, "op": "eq", "value": v} for k, v in (patch.get("set") or {}).items()]
        if patch.get("add_tags") or patch.get("replace_with"):
            checks.append({"field": "tags", "op": "has_tags",
                           "value": (patch.get("add_tags") or []) + (patch.get("replace_with") or [])})
        if patch.get("remove_tags"):
            checks.append({"field": "tags", "op": "lacks_tags", "value": patch["remove_tags"]})
        fails = run_checks(after, checks)
        return (not fails), (f"backup {bpath}" + ("" if not fails else "; verify failed: " + "; ".join(fails))), after
    if res == "team":
        cur = unwrap(c.get(f"/api/team/{int(rid)}"))
        bpath = backup(c, "team", rid, cur)
        members = list(cur.get("members") or [])
        remove = {str(x).lower() for x in patch.get("remove_members") or []}
        kept = [m for m in members if str(dig(m, "user.name") or dig(m, "user.email") or "").lower() not in remove
                and str(dig(m, "user.id")) not in remove]
        disabled = [dig(m, "user.name") for m in kept if m.get("disableLogin")]
        if disabled and not patch.get("accept_login_reset"):
            return False, (f"refused: {len(disabled)} remaining member(s) now have login disabled ({disabled[:5]}); "
                           "a team update would re-enable them. Re-plan with --accept-login-reset if intended."), cur
        by_id = {str(dig(m, "user.id")): m for m in kept}
        for add in patch.get("add_members") or []:
            m = by_id.get(str(add["user_id"]))
            if m is None:
                kept.append({"user": {"id": int(add["user_id"])}, "role": add["role"], "disableLogin": False})
            else:
                m["role"] = add["role"]          # existing member: change their role on this team
        body = team_request_body(cur)
        # The API sets each member's disableLogin from `enableLogin` without negating it, and an omitted
        # enableLogin means "login enabled". Omitting it keeps login-enabled members as they are; the planner
        # refuses (unless --accept-login-reset) when a member's login is currently disabled.
        body["members"] = [{"user": {"id": dig(m, "user.id")},
                            "role": (m.get("role") or {}).get("name") if isinstance(m.get("role"), dict) else m.get("role")}
                           for m in kept]
        # Membership changes go through /with-user, which applies them (and refuses changes to the caller's own
        # membership); plain PUT /api/team does not apply member changes reliably.
        c.request("PUT", "/api/team/with-user", body=body, idempotent=False)
        after = unwrap(c.get(f"/api/team/{int(rid)}"))
        got = {str(dig(m, "user.id")) for m in after.get("members") or []}
        want = {str(dig(m, "user.id")) for m in body["members"]}
        fails = [] if got == want else [f"members {sorted(got)} != expected {sorted(want)}"]
        want_roles = {str(dig(m, "user.id")): m["role"] for m in body["members"]}
        for m in after.get("members") or []:
            r = (m.get("role") or {}).get("name") if isinstance(m.get("role"), dict) else m.get("role")
            if str(dig(m, "user.id")) in want_roles and r != want_roles[str(dig(m, "user.id"))]:
                fails.append(f"user {dig(m, 'user.id')} has role {r!r}, expected {want_roles[str(dig(m, 'user.id'))]!r}")
        if scope_signature(after) != scope_signature(cur):
            fails.append("the team's access scope changed; restore it from the backup")
        return (not fails), f"backup {bpath}; members now {len(got)}" + ("" if not fails else "; " + "; ".join(fails)), after
    return False, f"unknown resource {res}", None


def team_request_body(t):
    """Convert a GET /api/team/{id} record into the shape PUT /api/team accepts."""
    props = []
    for pr in t.get("properties") or []:
        bu = pr.get("businessUnit") or {}
        props.append({"id": pr.get("id"), "businessUnitId": bu.get("id", pr.get("businessUnitId")),
                      "businessUnitName": bu.get("name", pr.get("businessUnitName")),
                      "productSubProductMap": pr.get("productSubProductMap") or [],
                      "accessOnAllProduct": pr.get("accessOnAllProduct", False), "groups": pr.get("groups") or []})
    body = {k: t.get(k) for k in ("id", "name", "description", "emailAlias", "approvalWorkflow", "tags",
                                  "businessOwner", "securityOwner", "engineeringOwner", "supportOwner",
                                  "complianceOwner", "lead") if t.get(k) is not None}
    body["properties"] = props
    return body


def scope_signature(t):
    sig = []
    for pr in t.get("properties") or []:
        prods = sorted(str(dig(m, "product.id")) for m in pr.get("productSubProductMap") or [])
        sig.append((str(dig(pr, "businessUnit.id") or pr.get("businessUnitId")), bool(pr.get("accessOnAllProduct")),
                    tuple(sorted(pr.get("groups") or [])), tuple(prods)))
    return sorted(sig)


def bulk_body(ids, fields, notes):
    body = {"notes": notes, "multiActionTagUpdates": [],
            "findingFilterRequest": {"filters": {"id_term": [int(i) for i in ids]}, "ignoreMitigated": False}}
    body.update(fields)
    return body


def exec_findings_bulk(c, step):
    ids, fields, notes = step["ids"], step["fields"], step["notes"]
    prog = APPLY_CTX["progress"]                     # survives a failed or interrupted apply (not signed)
    jobs = prog.setdefault("jobs", [])
    start = prog.get("sent_chunks", 0)
    if start:
        print(f"        resuming: {start} chunk(s) already sent, not re-sending them", file=sys.stderr)
    for n, i in enumerate(range(0, len(ids), ID_CHUNK)):
        if n < start:
            continue
        chunk = ids[i:i + ID_CHUNK]
        resp = c.request("PUT", "/user/findings/v2/bulk/change-basic-details", body=bulk_body(chunk, fields, notes),
                         idempotent=False)
        job = dig(unwrap(resp) or {}, "jobId") if isinstance(unwrap(resp), dict) else None
        if job:
            jobs.append(job)
        prog["sent_chunks"] = n + 1
        APPLY_CTX["save"]()
        print(f"        sent {min(len(ids), i + ID_CHUNK):,}/{len(ids):,}", file=sys.stderr)
    sent = len(ids)
    failed_ids, job_states = [], {}
    deadline = time.time() + ASYNC_VERIFY_TIMEOUT
    pending_jobs = list(jobs)
    while pending_jobs and time.time() < deadline:
        time.sleep(5)
        still = []
        for j in pending_jobs:
            st = unwrap(c.get(f"/api/v2/jobs/{j}")) or {}
            state = str(st.get("status") or "").upper()
            job_states[j] = state
            if state in ("COMPLETED", "FAILED"):
                failed_ids += st.get("failedFindingIds") or []
            else:
                still.append(j)
        pending_jobs = still
    if pending_jobs:
        return False, (f"{len(pending_jobs)} job(s) still running after {ASYNC_VERIFY_TIMEOUT}s ({pending_jobs[:3]}). "
                       "Nothing failed yet: re-run the same apply command later to re-check; it will not re-send."), None
    if any(v == "FAILED" for v in job_states.values()) or failed_ids:
        return False, (f"job(s) reported failures: states {sorted(set(job_states.values()))}, "
                       f"{len(failed_ids)} failed finding id(s) e.g. {failed_ids[:10]}. Check the key's permissions "
                       f"for this status/field and the finding ids."), None
    expect = step.get("expect") or {}
    sample = ids[:: max(1, len(ids) // 20)][:20]
    deadline = time.time() + ASYNC_VERIFY_TIMEOUT
    pending = list(sample)
    while pending and time.time() < deadline:
        time.sleep(10)
        still = []
        for fid in pending:
            f = unwrap(c.get(f"/user/findings/{int(fid)}"))
            if any(str(dig(f, k)).lower() != str(v).lower() for k, v in expect.items()):
                still.append(fid)
        pending = still
    ok = not pending
    msg = (f"sent {sent:,} ids in {(len(ids) + ID_CHUNK - 1) // ID_CHUNK} requests; jobs "
           f"{sorted(set(job_states.values())) or 'n/a'}; sample verify {len(sample) - len(pending)}/{len(sample)}")
    if pending:
        msg += (f". Not yet visible on {pending[:5]} after {ASYNC_VERIFY_TIMEOUT}s: the job may still be running. "
                "Re-check with `ac.py findings get ID` before concluding it failed.")
    return ok, msg, None


def exec_upload(c, step):
    path = Path(step["file"])
    if not path.exists():
        return False, f"file {path} no longer exists", None
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != step["sha256"]:
        return False, "file changed since the plan was made; re-plan", None
    tool = step["tool"]
    sd = step.get("scan_date") or (now_utc() - dt.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    body = {"product": int(step["group_id"]), "subProduct": int(step["subgroup_id"]), "scanDate": sd, "fileName": step["upload_name"], "environment": step["environment"],
            "uploadTimezone": "UTC"}
    d = c.request("POST", f"/user/tools/generic/configurations/{urllib.parse.quote(tool)}/upload", body=body,
                  idempotent=False)
    signed = (d or {}).get("signedUrl")
    if not signed:
        return False, f"no signedUrl in response: {str(d)[:300]}", d
    ctype = "text/csv" if path.suffix.lower() == ".csv" else "application/x-www-form-urlencoded"
    req = urllib.request.Request(signed, data=path.read_bytes(), method="PUT", headers={"Content-Type": ctype})
    with urllib.request.urlopen(req, timeout=600) as r:
        if r.status not in (200, 201, 204):
            return False, f"storage PUT returned {r.status}", None
    deadline = time.time() + step.get("wait_seconds", 600)
    q = urllib.parse.quote(json.dumps({}))
    while time.time() < deadline:
        time.sleep(15)
        rows = []
        for pg in range(3):            # a busy tenant can push the new scan past the first page
            page = c.get(f"/api/scans?scanReportReqDto={q}&page={pg}&size=100&sort=createdAt,desc") or {}
            rows += page.get("content") or []
            if any(r.get("fileName") == step["upload_name"] for r in rows):
                break
        for s in rows:
            if s.get("fileName") == step["upload_name"]:
                st = str(s.get("scanStatus") or s.get("status") or "").upper()
                if st in ("COMPLETED", "FAILED", "PASSED", "ERROR"):
                    fnd = s.get("findings") or {}
                    counts = {k: (fnd.get(k) or {}).get("count") for k in
                              ("newFindings", "duplicateFindings", "resolvedFindings", "totalFindings")}
                    ok = st in ("COMPLETED", "PASSED")
                    return ok, f"scan {s.get('id')} {st} {counts} {s.get('errorMessage') or ''}".strip(), s
    return False, ("uploaded, but the scan's result wasn't seen within the wait. Nothing will be re-sent if you "
                   "re-run apply; check `ac.py scans --file " + step["upload_name"] + " --pages 5` instead."), None


def exec_restore(c, step):
    res, rid, obj = step["resource"], step["id"], step["object"]
    if res == "group":
        cur = get_group(c, rid)
        bpath = backup(c, "group", rid, cur)
        c.request("PUT", "/user/product", body=prepare_group_body(obj), idempotent=False)
        after = get_group(c, rid)
        fails = run_checks(after, [{"field": "tags", "op": "has_tags", "value": obj.get("tags") or []}])
    elif res == "subgroup":
        cur = get_subgroup(c, rid)
        bpath = backup(c, "subgroup", rid, cur)
        c.request("PUT", "/api/sub-product", body=prepare_subgroup_body(obj), idempotent=False)
        after = get_subgroup(c, rid)
        fails = run_checks(after, [{"field": "tags", "op": "has_tags", "value": own_subgroup_tags(obj)}])
    else:
        return False, f"restore of {res} is not supported; use the backup JSON with `plan raw`", None
    return (not fails), f"backup of pre-restore state {bpath}" + ("" if not fails else "; " + "; ".join(fails)), after


def exec_create_subgroup(c, step):
    gid = step.get("group_id")
    if not gid:
        g = find_group_by_name(c, step["group_name"], working_bu(c))
        if not g:
            return False, f"group '{step['group_name']}' not found at apply time", None
        gid = g["id"]
    if any(str(s.get("name", "")).lower() == step["name"].lower() for s in subgroups_of(c, gid)):
        return True, "already exists (skipped)", None
    body = {"name": step["name"], "product": {"id": int(gid)}}
    if step.get("description"):
        body["description"] = step["description"]
    if step.get("tags"):
        body["tags"] = step["tags"]
    resp = c.request("POST", "/api/sub-product", body=body, idempotent=False)
    time.sleep(2)
    hit = [s for s in subgroups_of(c, gid) if str(s.get("name", "")).lower() == step["name"].lower()]
    if not hit:
        return False, "create returned but the subgroup is not listed yet; re-check before retrying", resp
    return True, f"subgroup id {hit[0]['id']}", resp


APPLY_CTX = {"progress": {}, "save": lambda: None}

EXECUTORS = {"request": exec_request, "merge": exec_merge, "findings-bulk": exec_findings_bulk,
             "upload": exec_upload, "restore": exec_restore, "create-subgroup": exec_create_subgroup}


# ----------------------------------------------------------------------------------------------- commands: profile

def cmd_profile(args):
    cfg = load_config()
    if args.action == "add":
        sources = [x for x in (args.token_env, args.token_keychain, args.token_file) if x]
        if len(sources) != 1:
            raise Refused("Give exactly one of --token-env, --token-keychain or --token-file.")
        base = (args.base_url or DEFAULT_BASE_URL).rstrip("/")
        if not base.startswith("https://"):
            raise Refused("The base URL must start with https://.")
        host = urllib.parse.urlparse(base).hostname or ""
        if not ARMORCODE_HOST_RE.search(host):
            print(f"WARNING: {host} is not an armorcode.com host. Continue only if this is your private ArmorCode "
                  "instance; the API key will be sent to it.", file=sys.stderr)
        prof = {"base_url": base, "mode": args.mode, "label": args.label or ""}
        if args.token_env:
            prof["token_env"] = args.token_env
        if args.token_keychain:
            prof["token_keychain"] = args.token_keychain
        if args.token_file:
            prof["token_file"] = args.token_file
        if args.business_unit:
            prof["business_unit_id"] = int(args.business_unit)
        cfg.setdefault("profiles", {})[args.name] = prof
        if args.default or not cfg.get("default"):
            cfg["default"] = args.name
        save_config(cfg)
        print(f"Saved profile '{args.name}' ({prof['mode']}) -> {prof['base_url']}. Test it with: ac.py --profile {args.name} ping")
    elif args.action == "list":
        for n, p in (cfg.get("profiles") or {}).items():
            src = p.get("token_env") and f"env:{p['token_env']}" or p.get("token_keychain") and \
                f"keychain:{p['token_keychain']}" or f"file:{p.get('token_file')}"
            star = "*" if n == cfg.get("default") else " "
            print(f"{star} {n:<14} {p.get('mode'):<11} {p.get('base_url'):<34} {src}  {p.get('label', '')}")
        if not cfg.get("profiles"):
            print("No profiles yet. Add one with `ac.py profile add NAME --token-env VAR --mode read-only`.")
    elif args.action == "use":
        if args.name not in (cfg.get("profiles") or {}):
            raise Refused(f"Profile '{args.name}' not found.")
        cfg["default"] = args.name
        save_config(cfg)
        print(f"Default profile is now '{args.name}'.")
    elif args.action == "remove":
        cfg.get("profiles", {}).pop(args.name, None)
        if cfg.get("default") == args.name:
            cfg["default"] = next(iter(cfg.get("profiles") or {}), None)
        save_config(cfg)
        print(f"Removed profile '{args.name}'. The token itself was not touched.")
    return EXIT_OK


# ----------------------------------------------------------------------------------------------- commands: reads

def cmd_ping(c, args):
    bus = business_units(c)
    count = c.get("/user/product/count")
    print(f"Connected to {c.base} as profile '{c.profile_name}' ({c.prof.get('mode')}"
          f"{' · ' + c.prof['label'] if c.prof.get('label') else ''})")
    print("Organizations (business units): " + ", ".join(f"{b.get('name')} [{b.get('id')}]" for b in bus))
    print(f"Groups visible to this key, all organizations: {count}")
    if c.rate_remaining is not None:
        print(f"Rate-limit headroom: {c.rate_remaining} requests left in the current window")
    if not c.writable:
        print("This profile is read-only: plans can be built and reviewed, but `apply` is refused.")
    return EXIT_OK


def cmd_get(c, args):
    params = dict(p.split("=", 1) for p in args.param or [])
    emit(c.get(args.path, params=params or None), args.out)
    return EXIT_OK


def cmd_query(c, args):
    path = args.path.split("?")[0].rstrip("/")
    if not any(re.fullmatch(p, path) for p in READ_ONLY_POSTS):
        raise Refused(f"{args.path} is not a known read-only POST endpoint, so it is treated as a change: build a plan "
                      f"with `ac.py plan raw POST {args.path} --body ...` and get the user's approval.")
    params = dict(p.split("=", 1) for p in args.param or [])
    body = load_body(args.body) or {}
    if re.fullmatch(r"/api/findings|/user/findings/(findingStats/all|findings-filters|under-review)", path) \
            and isinstance(body.get("filters"), dict):
        check_filters(body["filters"])
    emit(c.read_post(args.path, body, params=params or None), args.out)
    return EXIT_OK


def cmd_bus(c, args):
    emit(business_units(c), args.out)
    return EXIT_OK


def cmd_groups(c, args):
    bu = None if args.all_orgs else working_bu(c)
    rows = all_groups(c, bu, args.search)
    out = [{"id": g.get("id"), "name": g.get("name"), "tier": g.get("tier"), "status": g.get("status"),
            "subgroups": g.get("subProductCount"), "team": g.get("teamName"), "businessUnitId": g.get("businessUnitId"),
            "tags": g.get("tagList") or g.get("tags")} for g in rows]
    emit(out, args.out)
    print(f"{len(out)} groups", file=sys.stderr)
    return EXIT_OK


def cmd_group(c, args):
    g = get_group(c, args.id)
    if not args.full:
        g = {k: g.get(k) for k in ("id", "name", "description", "status", "tier", "classType", "type", "tags",
                                   "teamDto", "businessOwner", "securityOwner", "engineeringOwner", "supportOwner",
                                   "complianceOwner", "artifacts", "riskScore", "assetScore")}
        g["subgroups"] = subgroups_of(c, args.id)
    emit(g, args.out)
    return EXIT_OK


def cmd_subgroups(c, args):
    if args.group:
        emit(subgroups_of(c, args.group), args.out)
    else:
        rows, page = [], 0
        while True:
            body = {"pageNumber": page, "pageSize": 100}
            if args.search:
                body["search"] = args.search
            got = unwrap(c.read_post("/api/sub-product/name-id", body)) or []
            rows += got
            if len(got) < 100 or page > 500:
                break
            page += 1
        emit(rows, args.out)
    return EXIT_OK


def cmd_subgroup(c, args):
    s = get_subgroup(c, args.id)
    if not args.full:
        prod = s.get("product") or {}
        s = {"id": s.get("id"), "name": s.get("name"), "description": s.get("description"),
             "group": {"id": prod.get("id"), "name": prod.get("name")},
             "environments": [{"id": e.get("id"), "name": e.get("name")} for e in s.get("environmentDtos") or []],
             "own_tags": own_subgroup_tags(s),
             "inherited_tags": [t.get("tag") if isinstance(t, dict) else t
                                for t in (s.get("tagsMetaMap") or {}).get("PRODUCT") or []],
             "tool_tags": (s.get("tagsMetaMap") or {}).get("TOOL"), "riskScore": s.get("riskScore")}
    emit(s, args.out)
    return EXIT_OK


def build_tree(rows):
    tree = {}
    for r in rows:
        paths = [t.split(":", 1)[1] for t in r.get("tagList") or [] if norm_tag(t).startswith("armorcode.group:")]
        for p in paths or ["(no hierarchy tag)"]:
            node = tree
            for seg in [x for x in p.split("/") if x]:
                node = node.setdefault(seg, {"_groups": set(), "_subgroups": 0, "_children": {}})
                node["_subgroups"] += 1
                node["_groups"].add(r.get("productId"))
                node = node["_children"]
    return tree


def print_tree(tree, indent=0, max_depth=None):
    for name in sorted(tree):
        n = tree[name]
        print(f"{'  ' * indent}{name}  ({len(n['_groups'])} groups, {n['_subgroups']} subgroups)")
        if max_depth is None or indent + 1 < max_depth:
            print_tree(n["_children"], indent + 1, max_depth)


def lint_hierarchy(rows):
    issues = []
    by_norm = {}
    for r in rows:
        tags = [t for t in r.get("tagList") or [] if norm_tag(t).startswith("armorcode.group:")]
        if not tags:
            issues.append(f"subgroup {r['id']} '{r.get('name')}' (group '{r.get('productName')}') has no hierarchy tag")
        if len(tags) > 1:
            issues.append(f"subgroup {r['id']} '{r.get('name')}' sits in {len(tags)} hierarchy nodes: {tags}")
        for t in tags:
            path = t.split(":", 1)[1]
            key = re.sub(r"[\s/_-]+", "", path.lower())
            by_norm.setdefault(key, set()).add(path)
    for variants in by_norm.values():
        if len(variants) > 1:
            issues.append(f"near-duplicate hierarchy paths (differ only in spacing/separators): {sorted(variants)}")
    return issues


def cmd_hierarchy(c, args):
    rows = hierarchy_rows(c)
    if args.lint:
        issues = lint_hierarchy(rows)
        for i in issues[:200]:
            print(f"- {i}")
        print(f"{len(issues)} issue(s) across {len(rows)} subgroups" + (" (first 200 shown)" if len(issues) > 200 else ""))
        return EXIT_OK
    if args.out:
        emit(rows, args.out)
        return EXIT_OK
    print_tree(build_tree(rows), max_depth=args.depth)
    print(f"\n{len(rows)} subgroups. Paths come from armorcode.group tags (values are stored lowercase).")
    return EXIT_OK


def cmd_hierarchy_export(c, args):
    bu = working_bu(c)
    groups = {g["id"]: g for g in all_groups(c, bu)}
    rows = hierarchy_rows(c)
    by_group = {}
    for r in rows:
        if r.get("productId") in groups:
            by_group.setdefault(r["productId"], []).append(r)
    doc = {"format": "armorcode-hierarchy/v1", "exportedAt": iso(), "baseUrl": c.base, "businessUnitId": bu,
           "groups": []}
    for gid, g in sorted(groups.items(), key=lambda kv: str(kv[1].get("name")).lower()):
        subs = by_group.get(gid, [])
        gtags = (subs[0].get("productTagList") if subs else None) or g.get("tagList") or g.get("tags") or []
        entry = {"name": g.get("name"), "id": gid, "tier": g.get("tier"), "status": g.get("status"),
                 "description": g.get("description") or "",
                 "hierarchy": [t.split(":", 1)[1] for t in gtags if norm_tag(t).startswith("armorcode.group:")],
                 "tags": [t for t in gtags if not norm_tag(t).startswith("armorcode.group:")],
                 "subgroups": []}
        gset = {norm_tag(t) for t in gtags}
        for s in sorted(subs, key=lambda r: str(r.get("name")).lower()):
            own = [t for t in s.get("tagList") or [] if norm_tag(t) not in gset
                   and not norm_tag(t).startswith("armorcode.repo.")]
            entry["subgroups"].append({"name": s.get("name"), "id": s.get("id"), "tags": own})
        doc["groups"].append(entry)
    text = json.dumps(doc, indent=2, ensure_ascii=False)
    Path(args.out).expanduser().write_text(text, encoding="utf-8")
    print(f"Exported {len(doc['groups'])} groups / {sum(len(g['subgroups']) for g in doc['groups'])} subgroups "
          f"to {args.out}. Keep it in version control; edit it and run `ac.py plan hierarchy-sync --desired {args.out}`.")
    return EXIT_OK


def cmd_teams(c, args):
    emit(unwrap(c.get("/api/team/all-teams")), args.out)
    return EXIT_OK


def cmd_team(c, args):
    t = unwrap(c.get(f"/api/team/{int(args.id)}"))
    emit(t, args.out)
    return EXIT_OK


def cmd_users(c, args):
    body = {}                          # filter fields are top-level lists; a "filters" wrapper is ignored
    if args.email:
        body["searchEmail"] = [args.email]
    if args.name:
        body["searchName"] = [args.name]
    rows, page = [], 0
    while len(rows) < args.limit:
        d = unwrap(c.read_post("/api/v2/user/search", body,
                               params={"page": page, "size": min(100, args.limit), "sort": "email,asc"})) or {}
        got = d.get("content", []) if isinstance(d, dict) else d
        rows += got
        if len(got) < min(100, args.limit) or (isinstance(d, dict) and d.get("last")):
            break
        page += 1
    emit(rows[:args.limit], args.out)
    return EXIT_OK


def cmd_roles(c, args):
    emit(unwrap(c.get("/user/roles")), args.out)
    return EXIT_OK


def cmd_findings(c, args):
    filters = build_filters(args.aql, args.filters)
    if args.org:
        filters["businessUnit"] = [int(working_bu(c) if args.org == "pinned" else args.org)]
    if args.action == "count" and args.by:
        d = c.read_post("/user/findings/findingStats/all", {"filters": filters, "aggField": args.by,
                                                            "secAggField": "severity"}) or {}
        buckets = {k: v for k, v in (d.get("stats") or {}).items() if k != "Reported"}
        names = {}
        if args.by in ("product", "subProduct"):
            rows = hierarchy_rows(c)
            key, nm = ("productId", "productName") if args.by == "product" else ("id", "name")
            names = {str(r.get(key)): r.get(nm) for r in rows}
        out = sorted(({"key": k, "name": names.get(str(k), k), "count": v.get("count"), "bySeverity": v.get("severity")}
                      for k, v in buckets.items()), key=lambda r: -(r["count"] or 0))
        total = ((d.get("stats") or {}).get("Reported") or {}).get("count")
        emit({"total": total, "by": args.by, "buckets": out[:args.top] if args.top else out}, args.out)
        return EXIT_OK
    if args.action == "count":
        s = stats(c, filters)
        rep = s.get("Reported") or {}
        print(json.dumps({"total": rep.get("count"), "bySeverity": rep.get("severity"),
                          "byStatus": {k: v.get("count") for k, v in s.items() if k != "Reported"}}, indent=2))
        return EXIT_OK
    if args.action == "aql-check":
        if not args.aql:
            raise Refused("--aql is required")
        try:
            n = reported_count(c, {"aqlQueryV2": [args.aql]})
        except ApiError as e:
            print(f"INVALID: {e}")
            return EXIT_API
        scope = "" if re.search(r"\bstatus\b", args.aql, re.I) else " (no status condition, so every status is counted)"
        print(f"VALID: matches {n:,} findings{scope}.")
        if n == 0:
            clauses = [x.strip() for x in re.split(r"\s+AND\s+", args.aql, flags=re.I)]
            flat = re.sub(r"\b(?:IN|matchAny|matchAll|matchNone)\s*\([^()]*\)", "X", args.aql, flags=re.I)
            if len(clauses) > 1 and not re.search(r"\bOR\b|[()]", flat, re.I):
                print("Zero matches. Each condition on its own:")
                for cl in clauses:
                    try:
                        print(f"  {reported_count(c, {'aqlQueryV2': [cl]}):>12,}  {cl}")
                    except ApiError as e:
                        print(f"  {'invalid':>12}  {cl}  ({e})")
                print("A condition with 0 on its own is the one to question; otherwise the combination is empty.")
            else:
                print("Zero matches: check values (tags are lowercase; product/subProduct/team need numeric ids).")
        return EXIT_OK
    if args.action == "values":
        d = c.read_post("/user/findings/findings-filters", {"fields": [args.field], "filters": filters})
        emit(d.get(args.field, d) if isinstance(d, dict) else d, args.out)
        return EXIT_OK
    if args.action == "get":
        emit(unwrap(c.get(f"/user/findings/{int(args.id)}")), args.out)
        return EXIT_OK
    # list / export
    fields = [f.strip() for f in (args.fields or "id,severity,status,title,source,product.name,subProduct.name,"
                                  "environment.name,riskScore,cve,componentName,componentVersion,filePath,"
                                  "developer,foundOn,slaDueDate").split(",") if f.strip()]
    limit = args.limit or (None if args.out else PRINT_ROW_LIMIT)
    rows = []
    for f in iter_findings(c, filters, all_statuses=args.all_statuses, limit=limit):
        rows.append({k: epoch_ms_to_iso(dig(f, k)) if k in ("foundOn", "slaDueDate", "lastUpdated", "createdAt")
                     else dig(f, k) for k in fields})
    if not args.out and not args.limit and len(rows) >= PRINT_ROW_LIMIT:
        print(f"note: showing the first {PRINT_ROW_LIMIT}; use --out file.csv for everything or --limit N.",
              file=sys.stderr)
    if args.out and args.out.lower().endswith(".csv"):
        fd = os.open(str(Path(args.out).expanduser()), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fields)
            w.writeheader()
            for r in rows:
                w.writerow({k: ";".join(map(str, v)) if isinstance(v, list) else v for k, v in r.items()})
        print(f"Wrote {len(rows):,} findings to {args.out}")
    else:
        emit(rows, args.out)
    if not args.all_statuses and not args.aql:
        print("note: with plain --filters, MITIGATED (UI: Remediated) findings are left out; add --all-statuses "
              "to include them. (AQL queries return every status unless they restrict it.)", file=sys.stderr)
    return EXIT_OK


def cmd_scans(c, args):
    q = urllib.parse.quote(json.dumps({}))
    rows = []
    for pg in range(args.pages):
        page = c.get(f"/api/scans?scanReportReqDto={q}&page={pg}&size={args.limit}&sort=createdAt,desc") or {}
        rows += page.get("content") or []
        if page.get("last", True):
            break
    out = []
    for s in rows:
        if args.file and args.file not in str(s.get("fileName")):
            continue
        if args.tool and args.tool.lower() not in str(s.get("tool") or s.get("toolName") or "").lower():
            continue
        f = s.get("findings") or {}
        out.append({"id": s.get("id"), "fileName": s.get("fileName"), "tool": s.get("tool") or s.get("toolName"),
                    "status": s.get("scanStatus"), "error": s.get("errorMessage") or s.get("failureReason"),
                    "group": dig(s, "product.name"), "subgroup": dig(s, "subproduct.name"),
                    "environment": s.get("environment"), "trigger": s.get("triggerby"),
                    "new": dig(f, "newFindings.count"), "duplicate": dig(f, "duplicateFindings.count"),
                    "resolved": dig(f, "resolvedFindings.count"), "total": dig(f, "totalFindings.count"),
                    "createdAt": epoch_ms_to_iso(s.get("createdAt"))})
    emit(out, args.out)
    return EXIT_OK


def all_repos(c, repo_type=None):
    out, page = [], 0
    while True:
        d = c.get("/user/tools/git", params={"page": page, "size": 100}) or {}
        rows = d.get("content") or []
        out += [r for r in rows if not repo_type or str(r.get("repositoryType")).upper() == repo_type.upper()]
        if len(rows) < 100:            # this endpoint carries no `last` flag; a short page is the end
            return out
        page += 1


def cmd_repos(c, args):
    rows = all_repos(c, args.type)
    if args.unmapped:
        rows = [r for r in rows if not r.get("subProductId")]
    if args.search:
        rows = [r for r in rows if args.search.lower() in str(r.get("name")).lower()]
    emit([{k: r.get(k) for k in ("id", "name", "repositoryType", "repoStatusType", "productId", "subProductId",
                                 "environmentId", "lastCommitDays", "repoUrl")} for r in rows], args.out)
    print(f"{len(rows)} repositories", file=sys.stderr)
    return EXIT_OK


def cmd_job(c, args):
    emit(unwrap(c.get(f"/api/v2/jobs/{args.ref}")), args.out)
    return EXIT_OK


def cmd_spec(c, args):
    path = SPEC_DIR / f"{c.profile_name}.json"
    if args.action == "fetch" or not path.exists():
        ensure_home()
        spec = c.get("/v3/api-docs/ArmorCode", timeout=180)
        write_private(path, json.dumps(spec))
        print(f"Saved this tenant's OpenAPI spec ({len(spec.get('paths', {}))} paths) to {path}", file=sys.stderr)
        if args.action == "fetch":
            return EXIT_OK
    spec = json.loads(path.read_text(encoding="utf-8"))
    if args.action == "search":
        term = (args.term or "").lower()
        hits = 0
        for p, ops in sorted(spec.get("paths", {}).items()):
            for m, op in ops.items():
                if not isinstance(op, dict):
                    continue
                text = " ".join([p, op.get("summary", ""), op.get("operationId", ""), " ".join(op.get("tags", []))])
                if term in text.lower():
                    dep = " (deprecated)" if op.get("deprecated") else ""
                    print(f"{m.upper():<6} {p}  {op.get('summary', '')}{dep}")
                    hits += 1
        print(f"{hits} operations match '{args.term}'", file=sys.stderr)
        return EXIT_OK
    if args.action == "show":
        op = (spec.get("paths", {}).get(args.path) or {}).get(args.method.lower())
        if not op:
            print(f"{args.method.upper()} {args.path} is not in this tenant's published spec. It may be an internal "
                  "(UI) endpoint: see references/endpoint-catalog.md for its stability label.")
            return EXIT_API
        schemas = spec.get("components", {}).get("schemas", {})

        def resolve(o, depth=0):
            if isinstance(o, dict):
                if "$ref" in o and depth < 4:
                    return resolve(schemas.get(o["$ref"].split("/")[-1], {}), depth + 1)
                return {k: resolve(v, depth) for k, v in o.items()}
            if isinstance(o, list):
                return [resolve(v, depth) for v in o]
            return o
        emit(resolve(op), args.out)
        return EXIT_OK
    return EXIT_USAGE


# ----------------------------------------------------------------------------------------------- commands: plans

def plan_raw(c, args):
    method = args.method.upper()
    if method == "GET":
        raise Refused("GET requests don't change anything; use `ac.py get`.")
    body = load_body(args.body)
    params = dict(p.split("=", 1) for p in args.param or [])
    risk, why = classify_request(method, args.path, params)
    step = {"kind": "request", "method": method, "path": args.path, "body": body, "params": params or None,
            "summary": f"{method} {args.path}" + (f"?{urllib.parse.urlencode(params)}" if params else "")}
    target = args.path.split("?")[0]
    if method == "DELETE" and target.rstrip("/") == "/user/tools/generic/configurations" and "deleteAllData" not in params:
        raise Refused("Deleting a tool configuration defaults to deleteAllData=true, which purges that mapping's data "
                      "asynchronously. Add -p deleteAllData=false to remove only the mapping, or -p deleteAllData=true "
                      "if the user explicitly wants the purge.")
    if params.get("deleteAllData") in ("true", "True"):
        risk, why = "CRITICAL", "purges a tool configuration's data"
    if method in ("PUT", "PATCH", "DELETE") and re.search(r"/\d+$", target) and not args.no_backup:
        step["backup_get"] = target + ("?ignoreSubProducts=true" if target.startswith("/user/product/") else "")
    if args.verify_get:
        step["verify"] = {"get": args.verify_get, "wait": 3, "checks": []}
    hard = params.get("delete") in ("true", "True") or re.search(
        r"^/api/(team|runbook|custom-dashboard|risk-register|assessments)/\d+$", target)
    if method == "DELETE" and re.search(r"/\d+$", target) and hard:
        step["verify_gone"] = step.get("backup_get") or target
    preview = []
    if body is not None:
        preview = ["Request body:"] + ["  " + line for line in json.dumps(redact(body), indent=2).splitlines()[:60]]
    warnings, flags = [], {}
    if isinstance(body, dict):
        def walk(o):
            if isinstance(o, dict):
                for k, v in o.items():
                    yield k, v
                    yield from walk(v)
            elif isinstance(o, list):
                for v in o:
                    yield from walk(v)
        pairs = list(walk(body))
        if any(k == "rulesOnFutureFindingsEnabled" and v is True for k, v in pairs) and not args.allow_standing_rule:
            raise Refused("rulesOnFutureFindingsEnabled: true creates a standing rule that changes future findings "
                          "too. Re-plan with --allow-standing-rule only if the user explicitly wants that rule.")
        if any(k == "applyOnExistingData" and v is True for k, v in pairs) and not args.allow_backfill:
            raise Refused("applyOnExistingData: true runs this runbook on every existing matching finding when it is "
                          "enabled. Count the matches first, snapshot them (references/governance.md), then re-plan "
                          "with --allow-backfill if the user approves.")
        for fl in [body.get("filters"), dig(body, "findingFilterRequest.filters"),
                   dig(body, "scope.scopeFindingFilters.filters")]:
            if isinstance(fl, dict) and fl:
                check_filters(fl)
                if re.search(r"/findings", args.path):
                    n = len(fl["id_term"]) if isinstance(fl.get("id_term"), list) else reported_count(c, fl)
                    preview = [f"Findings matched by the filter: {n:,}"] + preview
                    if n == 0:
                        warnings.append("The filter matches 0 findings, so this change would do nothing. Plain filter "
                                        "values are case-sensitive (severity 'Critical', status 'OPEN'); check them "
                                        "with `ac.py findings count --filters ...`.")
                    if n > LARGE_BULK:
                        if not args.allow_large:
                            raise Refused(f"The filter matches {n:,} findings, above the {LARGE_BULK:,} safety cap. "
                                          "Narrow it or add --allow-large if the user explicitly approved that count.")
                        flags["allow_large"] = True
    if re.search(r"/runbook/\d+/run-now", args.path):
        warnings.append("Run-now acts on every finding the runbook's filter matches, even if the runbook is disabled.")
    if risk == "HIGH" and "full-object PUT" in why:
        warnings.append("Omitted fields are wiped by this endpoint. Prefer the merge helpers, which re-read the "
                        "object at apply time and keep every field you didn't change.")
    return new_plan(c, args.title or step["summary"], [step], risk, [why], warnings, preview, flags=flags)


def plan_group_update(c, args):
    g = get_group(c, args.id)
    patch = {"set": {}}
    for kv in args.set or []:
        k, v = kv.split("=", 1)
        if k == "tier":
            raise Refused("Use --tier ID (and --tier-tags) to change the tier.")
        if k not in GROUP_FIELDS_SETTABLE:
            raise Refused(f"--set {k} is not supported here (settable: {sorted(GROUP_FIELDS_SETTABLE)}); "
                          "use --type-id/--team-id/--owner or `plan raw` after reading references/org-model.md.")
        patch["set"][k] = v
    reasons = ["full-object update done as read-merge-write at apply time (no other field changes)"]
    warnings = []
    if args.tier:
        if not re.fullmatch(r"\d+", args.tier):
            raise Refused("--tier takes the tier id (1, 2, 3...), not 'Tier 1'. The UI shows N/A for a name.")
        patch["set"]["tier"] = args.tier
        if args.tier_tags:
            tier_tags, tiers = risk_tier_tags(c, args.tier)
            keys = {t.split(":", 1)[0].lower() for t in tier_tags}
            patch["remove_tags"] = [t for t in g.get("tags") or [] if t.split(":", 1)[0].lower() in keys
                                    and norm_tag(t) not in {norm_tag(x) for x in tier_tags}]
            patch["add_tags"] = tier_tags
        else:
            warnings.append("Setting tier via the API does not add the tier's risk tags, so the risk score won't "
                            "change. Add --tier-tags to write them (read from your tenant's RISK_TIERS).")
    if args.add_tag:
        patch["add_tags"] = (patch.get("add_tags") or []) + args.add_tag
    if args.remove_tag:
        patch["remove_tags"] = (patch.get("remove_tags") or []) + args.remove_tag
    if args.hierarchy is not None:
        patch["replace_prefix"] = "armorcode.group:"
        patch["replace_with"] = [f"armorcode.group:{h.strip().strip('/')}" for h in args.hierarchy if h.strip()]
        reasons.append("moves the group in the org hierarchy (changes team access scopes that match the old path)")
    if args.type_id:
        patch["type_id"] = args.type_id
    if args.team_id:
        patch["team_id"] = args.team_id
    owners = {}
    for o in args.owner or []:
        slot, uid = o.split("=", 1)
        if slot not in ("businessOwner", "securityOwner", "engineeringOwner", "supportOwner", "complianceOwner"):
            raise Refused(f"unknown owner slot {slot}")
        owners[slot] = uid
    if owners:
        patch["owners"] = owners
    if args.artifact:
        patch["artifacts_add"] = [{"name": a.split("=", 1)[0], "link": a.split("=", 1)[1]} for a in args.artifact]
    after = apply_group_patch(g, patch)
    diff = [f"{k}  {g.get(k)!r} -> {v!r}" for k, v in patch["set"].items() if str(g.get(k)) != str(v)]
    diff += tag_diff(g.get("tags"), after.get("tags"))
    if patch.get("type_id"):
        diff.append(f"type  {g.get('type')} -> {{'id': {patch['type_id']}}}")
    if patch.get("team_id"):
        diff.append(f"team  {dig(g, 'teamDto.id')} -> {patch['team_id']}")
    for s, u in owners.items():
        diff.append(f"{s}  {dig(g, s + '.id')} -> {u}")
    for a in patch.get("artifacts_add") or []:
        diff.append(f"artifact  + {a['name']} -> {a['link']}")
    if not diff:
        print("No change: the group already matches.")
        return None
    step = {"kind": "merge", "resource": "group", "id": int(args.id), "patch": patch, "diff": diff,
            "summary": f"Update group '{g.get('name')}' ({args.id})"}
    risk = "HIGH" if args.hierarchy is not None else "MEDIUM"
    return new_plan(c, f"Update group '{g.get('name')}' ({args.id})", [step], risk, reasons, warnings)


def plan_group_create(c, args):
    bu = working_bu(c)
    if find_group_by_name(c, args.name, bu):
        raise Refused(f"A group named '{args.name}' already exists in this organization.")
    tags = list(args.tag or []) + [f"armorcode.group:{h.strip().strip('/')}" for h in args.hierarchy or []]
    body = {"name": args.name, "description": args.description or "", "status": "Active"}
    if args.tier:
        body["tier"] = args.tier
        if args.tier_tags:
            tags += risk_tier_tags(c, args.tier)[0]
    if args.type_id:
        body["type"] = {"id": int(args.type_id)}
    body["tags"] = dedupe_tags(tags)
    step = {"kind": "request", "method": "POST", "path": "/user/product", "body": body,
            "summary": f"Create group '{args.name}'", "diff": [f"{k}: {v}" for k, v in body.items()]}
    warnings = []
    if not args.hierarchy:
        warnings.append("No --hierarchy given: the group will sit outside your org hierarchy until tagged.")
    return new_plan(c, f"Create group '{args.name}'", [step], "MEDIUM", ["creates a group"], warnings)


def plan_subgroup_create(c, args):
    g = get_group(c, args.group)
    if any(str(s.get("name", "")).lower() == args.name.lower() for s in subgroups_of(c, args.group)):
        raise Refused(f"Group '{g.get('name')}' already has a subgroup named '{args.name}'.")
    step = {"kind": "create-subgroup", "group_id": int(args.group), "name": args.name,
            "description": args.description, "tags": args.tag or [],
            "summary": f"Create subgroup '{args.name}' in group '{g.get('name')}' ({args.group})",
            "diff": [f"tags: {args.tag or []} (+ inherits the group's tags)"]}
    return new_plan(c, step["summary"], [step], "MEDIUM",
                    ["creates a subgroup (Production and Staging environments are created with it)"])


def plan_subgroup_update(c, args):
    s = get_subgroup(c, args.id)
    patch = {"set": {}}
    if args.name:
        patch["set"]["name"] = args.name
    if args.description is not None:
        patch["set"]["description"] = args.description
    if args.add_tag:
        patch["add_tags"] = args.add_tag
    if args.remove_tag:
        inherited = {norm_tag(t) for t in (s.get("tagsMetaMap") or {}).get("PRODUCT") or []}
        blocked = [t for t in args.remove_tag if norm_tag(t) in inherited]
        if blocked:
            raise Refused(f"{blocked} are inherited from the group; change them on the group instead.")
        patch["remove_tags"] = args.remove_tag
    if args.hierarchy is not None:
        patch["replace_prefix"] = "armorcode.group:"
        patch["replace_with"] = [f"armorcode.group:{h.strip().strip('/')}" for h in args.hierarchy if h.strip()]
    before = own_subgroup_tags(s)
    after = apply_subgroup_patch(s, patch)
    diff = [f"{k}  {s.get(k)!r} -> {v!r}" for k, v in patch["set"].items() if s.get(k) != v]
    diff += tag_diff(before, after["tags"])
    if not diff:
        print("No change: the subgroup already matches.")
        return None
    step = {"kind": "merge", "resource": "subgroup", "id": int(args.id), "patch": patch, "diff": diff,
            "summary": f"Update subgroup '{s.get('name')}' ({args.id})"}
    return new_plan(c, step["summary"], [step], "MEDIUM",
                    ["subgroup update done as read-merge-write at apply time (own tags only; group tags stay inherited)"])


def plan_subgroup_move(c, args):
    target = get_group(c, args.to_group)
    names = []
    for sid in args.ids:
        s = get_subgroup(c, sid)
        names.append(f"{s.get('name')} ({sid}) from '{dig(s, 'product.name')}'")
    step = {"kind": "request", "method": "POST", "path": "/api/sub-product/bulk/move",
            "body": {"subProductIds": [int(x) for x in args.ids], "productId": int(args.to_group)},
            "summary": f"Move {len(args.ids)} subgroup(s) to group '{target.get('name')}' ({args.to_group})",
            "diff": names[:12]}
    return new_plan(c, step["summary"], [step], "HIGH",
                    ["moves subgroups (and their findings) to another group; they take on the new group's "
                     "hierarchy, tier tags and team access"])


PRIOR_FIELDS = ("status", "severity", "product.id", "subProduct.id", "environment.id")


def resolve_finding_ids(c, args):
    """Return (ids, prior) where prior maps id -> the fields a bulk change can alter, captured before the change."""
    if args.max and args.max > LARGE_BULK and not args.allow_large:
        raise Refused(f"--max {args.max} is above the {LARGE_BULK:,} safety cap; add --allow-large if intended.")
    cap = args.max or LARGE_BULK
    if args.ids:
        ids = [int(x) for x in args.ids]
        if len(ids) > cap and not (args.allow_large and not args.max):
            raise Refused(f"{len(ids):,} ids is above the {cap:,} cap; add --allow-large (without --max) if intended.")
        queries = [f"id IN ({', '.join(map(str, ids[i:i + 500]))})" for i in range(0, len(ids), 500)]
    else:
        if not args.aql:
            raise Refused("Give --aql or --ids to select findings.")
        try:
            total = reported_count(c, {"aqlQueryV2": [args.aql]})
        except ApiError as e:
            raise Refused(f"The AQL is invalid: {e}")
        if total > cap and not args.max and not args.allow_large:
            raise Refused(f"The AQL matches {total:,} findings, above the {cap:,} safety cap. Narrow the query, pilot "
                          f"with --max 20, or re-run with --allow-large if the user explicitly wants all {total:,}.")
        if args.allow_large and not args.max:
            cap = total
        if total > cap:
            print(f"note: {total:,} findings match; this plan covers the first {cap:,} (--max).", file=sys.stderr)
        queries = [args.aql]
    prior = {}
    for q in queries:
        for f in iter_findings(c, {"aqlQueryV2": [q]}, all_statuses=True):
            prior[int(f["id"])] = {k: dig(f, k) for k in PRIOR_FIELDS}
            if len(prior) >= cap:
                break
        if len(prior) >= cap:
            break
    if args.ids:
        missing = [i for i in ids if i not in prior]
        if missing:
            raise Refused(f"{len(missing)} id(s) not found or not visible to this key: {missing[:10]}")
    return list(prior), prior


def plan_findings_update(c, args):
    fields, diff, expect = {}, [], {}
    if args.status:
        st = args.status.upper()
        if st not in FINDING_STATUSES:
            raise Refused(f"status must be one of {FINDING_STATUSES}")
        if st == "ACCEPTRISK":
            raise Refused("Accept-risk belongs in an exception (risk register) so it has an owner, a reason and an "
                          "expiry. See references/governance.md, 'Exceptions'.")
        fields["status"] = st
        expect["status"] = st
        diff.append(f"status -> {st}")
    if args.severity:
        sev = args.severity.upper()
        if sev not in SEVERITIES:
            raise Refused(f"severity must be one of {SEVERITIES}")
        fields["severity"] = sev
        expect["severity"] = sev
        diff.append(f"severity -> {sev}")
    if not fields:
        raise Refused("Nothing to change: give --status and/or --severity.")
    if not args.note:
        raise Refused("--note is required: it is stored on every finding as the reason for the change.")
    ids, prior = resolve_finding_ids(c, args)
    if not ids:
        print("No findings match; nothing to plan.")
        return None
    step = {"kind": "findings-bulk", "ids": ids, "fields": fields, "notes": args.note, "expect": expect,
            "prior": prior,
            "summary": f"Update {len(ids):,} findings in {(len(ids) + ID_CHUNK - 1) // ID_CHUNK} request(s)",
            "diff": diff + [f"selection: {args.aql or 'explicit ids'}", f"first ids: {ids[:8]}"]}
    flags = {"allow_large": len(ids) > LARGE_BULK}
    warnings = ["Bulk finding updates run as an async job: the API answers at once and findings change over the "
                "next 30-60+ seconds. apply re-reads a sample to confirm."]
    if args.status and args.status.upper() in ("FALSEPOSITIVE", "SUPPRESSED", "MITIGATED"):
        warnings.append("Closing statuses hide findings from default views and SLA reports.")
    return new_plan(c, f"Change {', '.join(diff)} on {len(ids):,} findings", [step], "HIGH",
                    ["changes findings in bulk"], warnings, flags=flags)


def plan_findings_move(c, args):
    sub = get_subgroup(c, args.to_subgroup)
    env = env_id_for(sub, args.env)
    if not env:
        raise Refused(f"Subgroup {args.to_subgroup} has no '{args.env}' environment "
                      f"(has: {[e.get('name') for e in sub.get('environmentDtos') or []]}).")
    gid = dig(sub, "product.id")
    if not args.note:
        raise Refused("--note is required for a move.")
    ids, prior = resolve_finding_ids(c, args)
    if not ids:
        print("No findings match; nothing to plan.")
        return None
    fields = {"product": int(gid), "subProduct": int(args.to_subgroup), "env": int(env)}
    step = {"kind": "findings-bulk", "ids": ids, "fields": fields, "notes": args.note, "prior": prior,
            "expect": {"subProduct.id": int(args.to_subgroup)},
            "summary": f"Move {len(ids):,} findings to '{dig(sub, 'product.name')} / {sub.get('name')}' ({args.env})",
            "diff": [f"selection: {args.aql or 'explicit ids'}", f"first ids: {ids[:8]}"]}
    return new_plan(c, step["summary"], [step], "HIGH", ["moves findings between subgroups"],
                    ["Moves are async: allow 30-60+ s before judging the result. Findings keep their status.",
                     "A later scan from the original tool mapping can recreate findings in the old subgroup "
                     "unless the tool mapping is changed too."],
                    flags={"allow_large": len(ids) > LARGE_BULK})


def plan_findings_revert(c, args):
    """Put status/severity back to the values captured in an earlier findings-update plan."""
    src, _ = load_plan(args.plan_id)
    if src.get("base_url") != c.base:
        raise Refused(f"Plan {args.plan_id} was for {src.get('base_url')}, not {c.base}.")
    bulk = [s for s in src["steps"] if s.get("kind") == "findings-bulk" and s.get("prior")]
    if not bulk:
        raise Refused("That plan has no findings-bulk step with captured prior values.")
    if not (src.get("applied_at") or any(r.get("ok") for r in src.get("results") or [])):
        raise Refused(f"Plan {src['id']} was never applied, so there is nothing to revert.")
    steps, skipped = [], {"changed since": 0, "no prior value": 0, "needs an exception": 0}
    for s in bulk:
        changed = [k for k in ("status", "severity") if k in s["fields"]]
        if not changed:
            raise Refused("Only status/severity changes can be reverted automatically. For a move, plan a "
                          "findings-move back to the original subgroup (prior subgroup ids are in the plan file).")
        ids = [int(x) for x in s["prior"]]
        current = {}
        for i in range(0, len(ids), 500):
            q = f"id IN ({', '.join(map(str, ids[i:i + 500]))})"
            for f in iter_findings(c, {"aqlQueryV2": [q]}, all_statuses=True):
                current[int(f["id"])] = f
        groups = {}
        for fid, pv in s["prior"].items():
            cur = current.get(int(fid)) or {}
            if any(str(cur.get(k)).upper() != str(s["fields"][k]).upper() for k in changed):
                skipped["changed since"] += 1       # someone or something changed it again; leave it
                continue
            if any(pv.get(k) in (None, "") for k in changed):
                skipped["no prior value"] += 1
                continue
            if "status" in changed and str(pv.get("status")).upper() == "ACCEPTRISK":
                skipped["needs an exception"] += 1
                continue
            key = tuple((k, str(pv.get(k)).upper()) for k in changed)
            groups.setdefault(key, []).append(int(fid))
        for key, ids in sorted(groups.items()):
            fields = dict(key)
            steps.append({"kind": "findings-bulk", "ids": ids, "fields": fields, "expect": fields,
                          "notes": args.note or f"Revert of {src['id']}",
                          "summary": f"Set {fields} on {len(ids):,} findings (revert {src['id']})"})
    n = sum(len(s["ids"]) for s in steps)
    if not steps:
        print(f"Nothing to revert: {skipped}")
        return None
    notes = [f"skipped {v} finding(s): {k}" for k, v in skipped.items() if v]
    return new_plan(c, f"Revert {src['id']}: {n:,} findings", steps, "HIGH", ["changes findings in bulk"],
                    ["Reverting restores status/severity only; notes and history entries from the original change remain."]
                    + notes, flags={"allow_large": n > LARGE_BULK})


def plan_exceptions(c, args):
    """One exception per group (+ environment) covering the findings an AQL selects. Exceptions are scoped to a
    single group, so 'accept CVE-X everywhere' becomes several exceptions in one plan."""
    try:
        total = reported_count(c, {"aqlQueryV2": [args.aql]})
    except ApiError as e:
        raise Refused(f"The AQL is invalid: {e}")
    cap = args.max or LARGE_BULK
    if total > cap and not args.allow_large:
        raise Refused(f"The AQL matches {total:,} findings (above {cap:,}). Narrow it, or add --allow-large --max N.")
    if not re.search(r"\bstatus\b", args.aql, re.I):
        raise Refused("Add a status condition (e.g. status IN ('OPEN','CONFIRMED','TRIAGE','IN_PROGRESS')) so closed "
                      "findings aren't pulled into the exception.")
    groups, sel = {}, {"aqlQueryV2": [args.aql]}
    if args.org:
        sel["businessUnit"] = [int(working_bu(c) if args.org == "pinned" else args.org)]
    for f in iter_findings(c, sel):
        key = (dig(f, "product.id"), dig(f, "environment.name") or "Production")
        g = groups.setdefault(key, {"name": dig(f, "product.name"), "subs": set(), "ids": []})
        g["subs"].add(dig(f, "subProduct.id"))
        g["ids"].append(int(f["id"]))
    if not groups:
        print("No findings match; nothing to plan.")
        return None
    end = args.end if "T" in args.end else args.end + "T23:59:59Z"
    steps = []
    for (gid, env), g in sorted(groups.items(), key=lambda kv: str(kv[1]["name"])):
        flt = args.aql if args.include_future else f"id IN ({', '.join(map(str, g['ids']))})"
        body = {"name": f"{args.name} - {g['name']}" + (f" ({env})" if env != "Production" else ""),
                "description": args.description or args.name, "startDate": iso(), "endDate": end,
                "reasons": [args.reason],
                "scope": {"productId": int(gid), "subProductIds": sorted(int(x) for x in g["subs"] if x),
                          "environmentName": env, "autoAddInScopeFinding": True,
                          "scopeFindingFilters": {"filters": {"aqlQueryV2": [flt]}}},
                "customWorkflow": [{"reviewerId": int(r), "reviewerType": "USER", "sequence": i}
                                   for i, r in enumerate(args.reviewer)],
                "subscribersUserIds": []}
        if args.approve_by:
            body["approveByDate"] = args.approve_by if "T" in args.approve_by else args.approve_by + "T23:59:59Z"
        steps.append({"kind": "request", "method": "POST", "path": "/api/risk-register", "body": body,
                      "summary": f"Exception '{body['name']}': {len(g['ids'])} finding(s) in group {gid} [{env}]",
                      "diff": [f"findings: {g['ids'][:8]}{' ...' if len(g['ids']) > 8 else ''}",
                               f"filter: {flt[:120]}"]})
    org_of = {g["id"]: g.get("businessUnitId") for g in all_groups(c, None)}
    here = working_bu(c)
    elsewhere = sorted({str(gid) for (gid, _) in groups if org_of.get(int(gid)) not in (None, here)})
    warnings = []
    if elsewhere:
        warnings.append(f"Groups {elsewhere} belong to another organization than {here}; creating exceptions there may "
                        "fail or need a key with Account Level Access. Use --org to limit the selection.")
    warnings += ["Each exception is created as a DRAFT. In-scope findings attach over the next 1-2 minutes; then "
                "submit with `plan exception-action submit --ids ...` (ids from `query /api/risk-register/filter`).",
                "Only the current reviewer can approve. Findings move to Accept Risk on approval only if the tenant's "
                "exception setting for that is on."]
    if args.include_future:
        warnings.append("--include-future: findings that match the AQL later are added to these exceptions too.")
    n = sum(len(g["ids"]) for g in groups.values())
    return new_plan(c, f"Create {len(steps)} exception(s) covering {n} finding(s): {args.name}", steps, "HIGH",
                    ["accepts risk on findings (after approval)"], warnings)


def plan_exception_action(c, args):
    steps = []
    for xid in args.ids:
        ex = unwrap(c.get(f"/api/risk-register/{int(xid)}"))
        body = {"notes": args.note} if args.action in ("submit", "approve", "reject") else None
        steps.append({"kind": "request", "method": "POST", "path": f"/api/risk-register/{int(xid)}/{args.action}",
                      "body": body, "summary": f"{args.action} exception {xid} '{ex.get('name')}' (now {ex.get('status')})"})
    risk = "HIGH" if args.action in ("approve", "archive") else "MEDIUM"
    return new_plan(c, f"{args.action.capitalize()} {len(steps)} exception(s)", steps, risk,
                    [f"{args.action}s exceptions"],
                    ["Approval emails go to requesters and subscribers and can lag for hours on bulk approvals."]
                    if args.action == "approve" else [])


def plan_scan_upload(c, args):
    path = Path(args.file).expanduser().resolve()
    if not path.exists():
        raise Refused(f"{path} does not exist")
    sub = get_subgroup(c, args.subgroup)
    gid = dig(sub, "product.id")
    envs = [e.get("name") for e in sub.get("environmentDtos") or []]
    if args.env not in envs:
        raise Refused(f"Subgroup has environments {envs}; '{args.env}' would be created silently. Use one of them.")
    existing = reported_count(c, {"source": [args.tool], "subProduct": [int(args.subgroup)],
                                  "environmentName": [args.env], "status": ["OPEN", "CONFIRMED", "TRIAGE", "IN_PROGRESS"]})
    sources = c.read_post("/user/findings/findings-filters", {"fields": ["source"],
                                                              "filters": {"subProduct": [int(args.subgroup)]}})
    known = [str(x.get("name") if isinstance(x, dict) else x) for x in (sources or {}).get("source") or []]
    upload_name = f"{now_utc().strftime('%Y%m%dT%H%M%S')}_{path.name}"
    step = {"kind": "upload", "tool": args.tool, "group_id": int(gid), "subgroup_id": int(args.subgroup),
            "environment": args.env, "file": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "upload_name": upload_name, "scan_date": args.scan_date,
            "summary": f"Upload {path.name} ({path.stat().st_size:,} bytes) as '{args.tool}' to "
                       f"'{dig(sub, 'product.name')} / {sub.get('name')}' [{args.env}]"}
    warnings = [f"REPLACE SEMANTICS: this upload becomes the current '{args.tool}' result for this subgroup + "
                f"environment. Findings from that tool that are not in the file are closed as MITIGATED. "
                f"{existing:,} active '{args.tool}' findings are there now."]
    if known and args.tool.lower() not in {k.lower() for k in known}:
        warnings.append(f"No findings in this subgroup carry source '{args.tool}' (sources here: {known[:6]}). If that "
                        "tool's findings appear under another name, the count above understates what gets closed.")
    if args.scan_date:
        warnings.append("scanDate must not be in the future (UTC) or the upload is rejected.")
    return new_plan(c, step["summary"], [step], "HIGH", ["uploads a scan"], warnings)


def repo_map_step(repo, sub, env_name, branch=None, code_scan=False, dependabot=False):
    env = env_id_for(sub, env_name)
    if not env:
        raise Refused(f"Subgroup {sub.get('id')} ('{sub.get('name')}') has no '{env_name}' environment.")
    body = {"id": repo["id"], "name": repo.get("name"), "repoType": repo.get("repositoryType"),
            "gitInstallationId": repo.get("gitInstallationId"), "repoUrl": repo.get("repoUrl"),
            "productId": int(dig(sub, "product.id")), "subProductId": int(sub["id"]), "environmentId": int(env),
            "branchName": branch or repo.get("branchName") or "main",
            "enableCodeScan": code_scan or bool(repo.get("enableCodeScan")),
            "enableDependabot": dependabot or bool(repo.get("enableDependabot")),
            "enableTicket": bool(repo.get("enableTicket"))}
    was = (f"{repo.get('productName')} / {repo.get('subProductName')}" if repo.get("subProductId") else "unmapped")
    return {"kind": "request", "method": "PUT", "path": f"/user/tools/git/token/{repo['id']}", "body": body,
            "summary": f"Map '{repo.get('name')}' -> '{dig(sub, 'product.name')} / {sub.get('name')}' [{env_name}]",
            "diff": [f"was: {was}", f"branch {body['branchName']}"],
            "prior": {k: repo.get(k) for k in ("productId", "subProductId", "environmentId", "branchName")}}


def plan_repo_map(c, args):
    repos = all_repos(c)
    by_id = {str(r["id"]): r for r in repos}
    by_name = {}
    for r in repos:
        by_name.setdefault(str(r.get("name", "")).lower(), []).append(r)

    def find_repo(key):
        r = by_id.get(str(key).strip())
        if r:
            return r
        hits = by_name.get(str(key).strip().lower()) or []
        if len(hits) == 1:
            return hits[0]
        raise Refused(f"Repository '{key}' " + ("matches several repositories; use its id." if hits else "not found."))

    pairs = []
    if args.csv:
        with open(Path(args.csv).expanduser(), newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                pairs.append((row.get("repo") or row.get("repo_id"), row.get("subgroup_id"),
                              row.get("environment") or args.env, row.get("branch") or args.branch))
    elif args.repo_id and args.subgroup:
        pairs.append((args.repo_id, args.subgroup, args.env, args.branch))
    else:
        raise Refused("Give REPO_ID --subgroup ID, or --csv with columns repo,subgroup_id[,branch,environment].")
    subs, steps, skipped = {}, [], []
    for key, sid, env_name, branch in pairs:
        repo = find_repo(key)
        if str(repo.get("subProductId")) == str(sid):
            skipped.append(repo.get("name"))
            continue
        if sid not in subs:
            subs[sid] = get_subgroup(c, sid)
        steps.append(repo_map_step(repo, subs[sid], env_name, branch, args.code_scan, args.dependabot))
    if not steps:
        print(f"Nothing to change: {len(skipped)} repositories are already mapped as requested.")
        return None
    remaps = sum(1 for s in steps if not s["diff"][0].endswith("unmapped"))
    warnings = ["Map repositories before ingesting their findings: developer attribution (git blame) is resolved "
                "at ingestion time."]
    if remaps:
        warnings.append(f"{remaps} repositor{'y is' if remaps == 1 else 'ies are'} currently mapped elsewhere and "
                        "will be re-pointed. Findings already ingested stay where they are.")
    title = steps[0]["summary"] if len(steps) == 1 else f"Map {len(steps)} repositories to subgroups"
    return new_plan(c, title, steps, "MEDIUM" if not remaps else "HIGH",
                    ["maps SCM repositories to subgroups"], warnings,
                    [f"{len(skipped)} already mapped as requested (skipped)"] if skipped else [])


def plan_team_members(c, args):
    t = unwrap(c.get(f"/api/team/{int(args.id)}"))
    adds = []
    for a in args.add or []:
        uid, role = a.split(":", 1) if ":" in a else (a, None)
        if not role:
            raise Refused("--add takes USER_ID:ROLE_NAME (a member's role is per team).")
        adds.append({"user_id": int(uid), "role": role})
    patch = {"add_members": adds, "remove_members": args.remove or [], "accept_login_reset": args.accept_login_reset}
    existing = {str(dig(m, "user.id")): m for m in t.get("members") or []}
    diff = [(f"~ user {a['user_id']} role -> {a['role']}" if str(a["user_id"]) in existing else
             f"+ user {a['user_id']} as {a['role']}") for a in adds] + [f"- {r}" for r in args.remove or []]
    removing = {str(r).lower() for r in args.remove or []}
    disabled = [dig(m, "user.name") for m in t.get("members") or [] if m.get("disableLogin")
                and str(dig(m, "user.id")) not in removing and str(dig(m, "user.name")).lower() not in removing]
    if disabled and not args.accept_login_reset:
        raise Refused(f"{len(disabled)} member(s) of this team have login disabled ({disabled[:5]}). Any team update "
                      "re-enables login for every listed member. Re-run with --accept-login-reset only if the user "
                      "accepts that, then disable their login again afterwards.")
    now = len(t.get("members") or [])
    after = now + len([a for a in adds if str(a["user_id"]) not in {str(dig(m, "user.id")) for m in t.get("members") or []}])
    after -= len([m for m in t.get("members") or [] if str(dig(m, "user.id")) in removing
                  or str(dig(m, "user.name")).lower() in removing])
    step = {"kind": "merge", "resource": "team", "id": int(args.id), "patch": patch, "diff": diff,
            "summary": f"Change members of team '{t.get('name')}' ({args.id}): {now} -> {after} member(s)"}
    return new_plan(c, step["summary"], [step], "HIGH",
                    ["changes access control (the API replaces the whole member list; this re-reads and merges, "
                     "and cannot change your own membership)"],
                    ["Team writes can re-enable login for members whose login was disabled; check afterwards."])


def plan_restore(c, args):
    data = json.loads(Path(args.file).expanduser().read_text(encoding="utf-8"))
    if data.get("base_url") != c.base:
        raise Refused(f"Backup is from {data.get('base_url')}, not {c.base}.")
    res, rid, obj = data["resource"], data["id"], data["object"]
    if res == "group":
        cur = get_group(c, rid)
        diff = tag_diff(cur.get("tags"), obj.get("tags")) + [
            f"{k}  {cur.get(k)!r} -> {obj.get(k)!r}" for k in ("name", "description", "status", "tier", "classType")
            if cur.get(k) != obj.get(k)]
    elif res == "subgroup":
        cur = get_subgroup(c, rid)
        diff = tag_diff(own_subgroup_tags(cur), own_subgroup_tags(obj)) + [
            f"{k}  {cur.get(k)!r} -> {obj.get(k)!r}" for k in ("name", "description") if cur.get(k) != obj.get(k)]
    else:
        raise Refused(f"Restoring a {res} is not automated. Read the backup and build a `plan raw` from it.")
    step = {"kind": "restore", "resource": res, "id": rid, "object": obj, "diff": diff or ["(no visible differences)"],
            "summary": f"Restore {res} {rid} to the backup taken {data.get('taken_at')}"}
    return new_plan(c, step["summary"], [step], "HIGH", ["overwrites the object with a backed-up copy"])


def plan_hierarchy_sync(c, args):
    desired = json.loads(Path(args.desired).expanduser().read_text(encoding="utf-8"))
    bu = working_bu(c)
    groups = all_groups(c, bu)
    by_name = {}
    for g in groups:
        by_name.setdefault(str(g.get("name", "")).strip().lower(), []).append(g)
    rows = hierarchy_rows(c)
    subs_by_group, group_of_sub = {}, {}
    for r in rows:
        subs_by_group.setdefault(r.get("productId"), {})[str(r.get("name", "")).strip().lower()] = r
        group_of_sub.setdefault(str(r.get("name", "")).strip().lower(), []).append(r)
    steps, notes, counts = [], [], {"create_group": 0, "update_group": 0, "create_subgroup": 0,
                                    "update_subgroup": 0, "move_subgroup": 0}
    desired_names = set()
    for dg in desired.get("groups") or []:
        name = dg["name"].strip()
        desired_names.add(name.lower())
        h_tags = [f"armorcode.group:{h.strip().strip('/')}" for h in dg.get("hierarchy") or []]
        want_tags = dedupe_tags(h_tags + list(dg.get("tags") or []))
        matches = by_name.get(name.lower()) or []
        if len(matches) > 1:
            notes.append(f"'{name}': {len(matches)} groups share this name; skipped (resolve by hand)")
            continue
        if not matches:
            body = {"name": name, "description": dg.get("description") or "", "status": dg.get("status") or "Active",
                    "tags": want_tags}
            if dg.get("tier"):
                body["tier"] = str(dg["tier"])
            steps.append({"kind": "request", "method": "POST", "path": "/user/product", "body": body,
                          "summary": f"Create group '{name}'", "diff": [f"tags: {want_tags}"]})
            counts["create_group"] += 1
            for ds in dg.get("subgroups") or []:
                steps.append({"kind": "create-subgroup", "group_name": name, "name": ds["name"],
                              "tags": ds.get("tags") or [], "summary": f"Create subgroup '{ds['name']}' in '{name}'"})
                counts["create_subgroup"] += 1
            continue
        g = matches[0]
        gid = g["id"]
        cur = get_group(c, gid)
        patch, diff = {"set": {}}, []
        if dg.get("hierarchy") is not None:
            cur_h = sorted(norm_tag(t) for t in cur.get("tags") or [] if norm_tag(t).startswith("armorcode.group:"))
            if cur_h != sorted(norm_tag(t) for t in h_tags):
                patch["replace_prefix"], patch["replace_with"] = "armorcode.group:", h_tags
        extra = [t for t in dg.get("tags") or [] if norm_tag(t) not in {norm_tag(x) for x in cur.get("tags") or []}]
        if extra:
            patch["add_tags"] = extra
        if args.exact_tags:
            keep = {norm_tag(t) for t in want_tags}
            patch["remove_tags"] = [t for t in cur.get("tags") or [] if norm_tag(t) not in keep
                                    and not norm_tag(t).startswith("armorcode.group:")]
        for k in ("tier", "description", "status"):
            if dg.get(k) not in (None, "") and str(dg[k]) != str(cur.get(k) or ""):
                patch["set"][k] = str(dg[k])
        after = apply_group_patch(cur, patch)
        diff = [f"{k}  {cur.get(k)!r} -> {v!r}" for k, v in patch["set"].items()] + tag_diff(cur.get("tags"), after["tags"])
        if diff:
            steps.append({"kind": "merge", "resource": "group", "id": gid, "patch": patch, "diff": diff,
                          "summary": f"Update group '{name}' ({gid})"})
            counts["update_group"] += 1
        existing = subs_by_group.get(gid, {})
        listed = {d["name"].strip().lower() for d in dg.get("subgroups") or []}
        unlisted = [r.get("name") for k, r in existing.items() if k not in listed]
        if dg.get("subgroups") is not None and unlisted:
            notes.append(f"'{name}' has {len(unlisted)} subgroup(s) not in the file (left alone): {unlisted[:5]}")
        for ds in dg.get("subgroups") or []:
            key = ds["name"].strip().lower()
            if key in existing:
                r = existing[key]
                eff = {norm_tag(t) for t in r.get("tagList") or []}
                missing = [t for t in ds.get("tags") or [] if norm_tag(t) not in eff]
                if missing:
                    steps.append({"kind": "merge", "resource": "subgroup", "id": r["id"],
                                  "patch": {"add_tags": missing}, "diff": [f"tags  + {t}" for t in missing],
                                  "summary": f"Tag subgroup '{ds['name']}' ({r['id']})"})
                    counts["update_subgroup"] += 1
                continue
            elsewhere = [r for r in group_of_sub.get(key, []) if r.get("productId") != gid]
            if elsewhere and args.move_misplaced and len(elsewhere) == 1:
                r = elsewhere[0]
                steps.append({"kind": "request", "method": "POST", "path": "/api/sub-product/bulk/move",
                              "body": {"subProductIds": [r["id"]], "productId": gid},
                              "summary": f"Move subgroup '{ds['name']}' ({r['id']}) from '{r.get('productName')}' to '{name}'"})
                counts["move_subgroup"] += 1
                continue
            if elsewhere:
                notes.append(f"subgroup '{ds['name']}' exists under {[r.get('productName') for r in elsewhere]}, "
                             f"not '{name}' (re-run with --move-misplaced to move it, or rename it in the file)")
                continue
            steps.append({"kind": "create-subgroup", "group_id": gid, "name": ds["name"], "tags": ds.get("tags") or [],
                          "summary": f"Create subgroup '{ds['name']}' in '{name}'"})
            counts["create_subgroup"] += 1
    extras = [g.get("name") for g in groups if str(g.get("name", "")).strip().lower() not in desired_names]
    if not steps:
        print("The tenant already matches the desired hierarchy file." + (f" ({len(notes)} notes below)" if notes else ""))
        for n in notes:
            print(f"- {n}")
        return None
    preview = [", ".join(f"{v} {k.replace('_', ' ')}" for k, v in counts.items() if v)]
    if extras:
        preview.append(f"{len(extras)} groups exist in the tenant but not in the file; they are left alone "
                       f"(this tool never deletes). e.g. {extras[:5]}")
    risk = "HIGH" if counts["move_subgroup"] or any("replace_prefix" in (s.get("patch") or {}) for s in steps) else "MEDIUM"
    return new_plan(c, f"Sync hierarchy from {Path(args.desired).name}", steps, risk,
                    ["creates/updates groups and subgroups to match a desired-state file"],
                    notes[:50], preview)


PLANNERS = {"raw": plan_raw, "group-update": plan_group_update, "group-create": plan_group_create,
            "subgroup-create": plan_subgroup_create, "subgroup-update": plan_subgroup_update,
            "subgroup-move": plan_subgroup_move, "findings-update": plan_findings_update,
            "findings-move": plan_findings_move, "findings-revert": plan_findings_revert,
            "exceptions": plan_exceptions, "exception-action": plan_exception_action, "scan-upload": plan_scan_upload, "repo-map": plan_repo_map,
            "team-members": plan_team_members, "restore": plan_restore, "hierarchy-sync": plan_hierarchy_sync}


def cmd_plan(c, args):
    plan = PLANNERS[args.kind](c, args)
    if plan:
        render_plan(plan)
    return EXIT_OK


def cmd_plans(c, args):
    if args.id:
        plan, _ = load_plan(args.id)
        render_plan(plan, max_steps=10000)
        if plan.get("results"):
            print("\nResults:")
            for r in plan["results"]:
                print(f"  step {r['step']}: {'ok' if r['ok'] else 'FAILED'}  {r.get('detail', '')}")
        return EXIT_OK
    for p in sorted(PLANS_DIR.glob("p-*.json"), reverse=True)[:args.limit]:
        d = json.loads(p.read_text(encoding="utf-8"))
        done = sum(1 for r in d.get("results") or [] if r.get("ok"))
        state = "applied" if d.get("applied_at") else (f"partial {done}/{len(d['steps'])}" if done else "not applied")
        print(f"{d['id']}  {d['risk']:<8} {state:<14} {d['profile']:<10} {d['title']}")
    return EXIT_OK


def cmd_apply(c, args):
    plan, ppath = load_plan(args.plan_id)
    if plan.get("applied_at"):
        raise Refused(f"Plan {plan['id']} was already applied at {plan['applied_at']}. Build a new plan.")
    if plan["base_url"] != c.base or plan["profile"] != c.profile_name:
        raise Refused(f"Plan was built for {plan['profile']} ({plan['base_url']}), not {c.profile_name} ({c.base}).")
    if not c.writable:
        raise Refused(f"Profile '{c.profile_name}' is read-only. Changes need a read-write profile "
                      f"(`ac.py profile add NAME --mode read-write ...`), created deliberately by the user.")
    if not hmac.compare_digest(plan_hash(plan), plan.get("hash", "")):
        raise Refused("The plan file was modified after it was created (or on another machine). Build a new plan.")
    if args.confirm != plan["hash"][:6]:
        raise Refused("Confirmation code does not match this plan. Show the user the plan and use the code it prints.")
    age = now_utc() - dt.datetime.strptime(plan["created"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    if age > dt.timedelta(hours=PLAN_TTL_HOURS):
        raise Refused(f"Plan is {age} old (limit {PLAN_TTL_HOURS} h). Rebuild it so the dry run reflects the tenant.")
    if plan["risk"] == "CRITICAL" and not args.allow_destructive:
        raise Refused("This plan is CRITICAL (destructive). Re-run with --allow-destructive only if the user "
                      "explicitly approved the destructive action.")
    if (plan.get("flags") or {}).get("allow_large") and not args.allow_large:
        raise Refused("This plan changes more than the bulk safety cap. Re-run with --allow-large only if the user "
                      "explicitly approved the full count.")
    done = {r["step"] for r in plan.get("results") or [] if r.get("ok")}
    c.allow_writes = True
    print(f"Applying {plan['id']}: {plan['title']}  ->  {c.base} [{c.profile_name}]")
    if done:
        print(f"Resuming: steps {sorted(done)} already succeeded.")
    failed = False
    for i, step in enumerate(plan["steps"], 1):
        if i in done:
            continue
        label = step.get("summary") or step.get("kind")
        APPLY_CTX["progress"] = plan.setdefault("progress", {}).setdefault(str(i), {})
        APPLY_CTX["save"] = lambda: write_private(ppath, json.dumps(plan, indent=2, default=str))
        try:
            ok, detail, _ = EXECUTORS[step["kind"]](c, step)
            status = "ok" if ok else "verify-failed"
        except ApiError as e:
            ok, detail, status = False, str(e), e.status
        except Refused as e:
            ok, detail, status = False, str(e), "refused"
        except Exception as e:          # never leave a step without a result and an audit entry
            ok, detail, status = False, f"{type(e).__name__}: {c._scrub(str(e))}", "error"
        print(f"  {i:>3}/{len(plan['steps'])} {'OK  ' if ok else 'FAIL'} {label}" + (f"\n        {detail}" if detail else ""))
        audit(c, plan, i, step, status, ok, detail)
        plan.setdefault("results", []).append({"step": i, "ok": ok, "detail": detail, "at": iso()})
        write_private(ppath, json.dumps(plan, indent=2, default=str))
        if not ok:
            failed = True
            print(f"\nStopped at step {i}. Fix the cause, then re-run the same apply command to resume "
                  f"(completed steps are skipped).")
            break
    if not failed:
        plan["applied_at"] = iso()
        write_private(ppath, json.dumps(plan, indent=2, default=str))
        print(f"\nDone. Audit log: {AUDIT_FILE}   Backups: {BACKUPS_DIR}")
    return EXIT_VERIFY if failed else EXIT_OK


def cmd_backups(c, args):
    for p in sorted(BACKUPS_DIR.glob("*.json"), reverse=True)[:args.limit]:
        print(p)
    return EXIT_OK


def cmd_audit(c, args):
    if not AUDIT_FILE.exists():
        print("No changes have been applied from this machine yet.")
        return EXIT_OK
    lines = AUDIT_FILE.read_text(encoding="utf-8").splitlines()[-args.tail:]
    for line in lines:
        e = json.loads(line)
        print(f"{e['ts']}  {e['profile']:<10} {'ok  ' if e['ok'] else 'FAIL'} {e['plan']}  step {e['step']}  "
              f"{e.get('method') or e.get('kind')} {e.get('path') or ''}  {e['title']}")
    return EXIT_OK


# ----------------------------------------------------------------------------------------------- argument parsing

def build_parser():
    ap = argparse.ArgumentParser(prog="ac.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", help="profile name (default: ARMORCODE_PROFILE or the configured default)")
    ap.add_argument("--version", action="version", version=f"ac.py {VERSION}")
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("profile", help="manage tenant profiles (no token values are stored)")
    p.add_argument("action", choices=["add", "list", "use", "remove"])
    p.add_argument("name", nargs="?")
    p.add_argument("--base-url")
    p.add_argument("--token-env", help="NAME of the environment variable that holds the API key")
    p.add_argument("--token-keychain", help="macOS Keychain service name holding the API key")
    p.add_argument("--token-file", help="path to a chmod-600 file holding the API key")
    p.add_argument("--mode", choices=["read-only", "read-write"], default="read-only")
    p.add_argument("--label", help="shown on every plan, e.g. PRODUCTION")
    p.add_argument("--business-unit", help="pin an organization (business unit) id")
    p.add_argument("--default", action="store_true")

    def with_out(sp):
        sp.add_argument("--out", help="write the full result to this file instead of printing it")
        return sp

    sub.add_parser("ping", help="check connectivity, organizations and rate-limit headroom")
    with_out(sub.add_parser("bus", help="list organizations (business units)"))
    sp = with_out(sub.add_parser("get", help="GET any endpoint"))
    sp.add_argument("path")
    sp.add_argument("-p", "--param", action="append", help="query parameter k=v (repeatable)")
    sp = with_out(sub.add_parser("query", help="POST to a known read-only search/list/stats endpoint"))
    sp.add_argument("path")
    sp.add_argument("--body", help="JSON, @file.json or - for stdin")
    sp.add_argument("-p", "--param", action="append")

    sp = with_out(sub.add_parser("groups", help="list groups in the working organization"))
    sp.add_argument("--search")
    sp.add_argument("--all-orgs", action="store_true", help="include every organization (incl. Archive)")
    sp = with_out(sub.add_parser("group", help="show one group"))
    sp.add_argument("id")
    sp.add_argument("--full", action="store_true")
    sp = with_out(sub.add_parser("subgroups", help="list a group's subgroups (or search by name)"))
    sp.add_argument("--group")
    sp.add_argument("--search")
    sp = with_out(sub.add_parser("subgroup", help="show one subgroup (own vs inherited tags, environment ids)"))
    sp.add_argument("id")
    sp.add_argument("--full", action="store_true")
    sp = with_out(sub.add_parser("hierarchy", help="show the org hierarchy tree (or --lint it)"))
    sp.add_argument("--lint", action="store_true", help="report missing, multiple and near-duplicate paths")
    sp.add_argument("--depth", type=int, help="limit tree depth")
    sp = sub.add_parser("hierarchy-export", help="export groups/subgroups/hierarchy as a desired-state JSON file")
    sp.add_argument("--out", required=True)
    with_out(sub.add_parser("teams", help="list teams"))
    sp = with_out(sub.add_parser("team", help="show one team with members and scope"))
    sp.add_argument("id")
    sp = with_out(sub.add_parser("users", help="search users"))
    sp.add_argument("--email")
    sp.add_argument("--name")
    sp.add_argument("--limit", type=int, default=100)
    with_out(sub.add_parser("roles", help="list roles"))

    sp = with_out(sub.add_parser("findings", help="count, list, export and inspect findings",
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog="""actions:
  count       total + by status/severity; --by FIELD for a breakdown (product, subProduct, source, ...)
  list        rows with --fields (dot paths), --limit, --out file.csv|.json
  values      distinct values of --field under the filter
  get ID      one finding in full
  aql-check   validate --aql; returns the match count, or the exact error; breaks down zero-match queries
selection: --aql (preferred) and/or --filters JSON; --org ID|pinned limits to one organization.
AQL returns every status unless it restricts status; plain --filters skip MITIGATED unless --all-statuses."""))
    sp.add_argument("action", choices=["count", "list", "values", "get", "aql-check"])
    sp.add_argument("id", nargs="?", help="finding id (for get)")
    sp.add_argument("--aql", help="AQL v2 query, e.g. \"severity IN ('Critical') AND status IN ('OPEN')\"")
    sp.add_argument("--filters", help="raw filters JSON (or @file)")
    sp.add_argument("--field", help="field for `values`, e.g. source, subProduct, componentName")
    sp.add_argument("--fields", help="comma-separated dot paths for `list`")
    sp.add_argument("--limit", type=int, help="stop after N findings")
    sp.add_argument("--all-statuses", action="store_true", help="include MITIGATED (UI: Remediated) findings")
    sp.add_argument("--by", help="for count: break down by a field (source, product, subProduct, status, severity, "
                                 "scanType, environmentName, developer, ...)")
    sp.add_argument("--top", type=int, help="for count --by: keep the N largest buckets")
    sp.add_argument("--org", help="limit to one organization (business unit id, or 'pinned' for the profile's)")

    sp = with_out(sub.add_parser("scans", help="recent scans with new/duplicate/resolved counts"))
    sp.add_argument("--file")
    sp.add_argument("--tool")
    sp.add_argument("--limit", type=int, default=100, help="scans per page")
    sp.add_argument("--pages", type=int, default=1, help="pages to read, newest first")
    sp = with_out(sub.add_parser("repos", help="SCM repositories and their subgroup mapping"))
    sp.add_argument("--unmapped", action="store_true")
    sp.add_argument("--type", help="GITHUB, GITLAB, BITBUCKET or AZURE_REPOS")
    sp.add_argument("--search")
    sp = with_out(sub.add_parser("job", help="status of an async job"))
    sp.add_argument("ref")
    sp = with_out(sub.add_parser("spec", help="fetch/search/show this tenant's OpenAPI spec"))
    sp.add_argument("action", choices=["fetch", "search", "show"])
    sp.add_argument("term", nargs="?", help="search term, or METHOD for show")
    sp.add_argument("path", nargs="?", help="path for show")

    pp = sub.add_parser("plan", help="build a change plan (dry run; nothing is sent)")
    ps = pp.add_subparsers(dest="kind", required=True)
    x = ps.add_parser("raw", help="any POST/PUT/PATCH/DELETE")
    x.add_argument("method", help="POST, PUT, PATCH or DELETE")
    x.add_argument("path", help="API path, e.g. /api/runbook/123/disable")
    x.add_argument("--body", help="JSON, @file.json or - for stdin")
    x.add_argument("-p", "--param", action="append", help="query parameter k=v (repeatable)")
    x.add_argument("--title", help="one-line description shown in the plan and audit log")
    x.add_argument("--verify-get", help="GET path to re-read after applying")
    x.add_argument("--no-backup", action="store_true", help="skip the automatic pre-change snapshot")
    x.add_argument("--allow-large", action="store_true", help="filter may match more than the bulk safety cap")
    x.add_argument("--allow-standing-rule", action="store_true", help="permit rulesOnFutureFindingsEnabled: true")
    x.add_argument("--allow-backfill", action="store_true", help="permit applyOnExistingData: true on a runbook")
    x = ps.add_parser("group-update")
    x.add_argument("id")
    x.add_argument("--set", action="append", help="field=value for name, description, status, tier, classType")
    x.add_argument("--tier", help="tier id: 1, 2, 3 ...")
    x.add_argument("--tier-tags", action="store_true", help="also write the tier's risk tags from RISK_TIERS")
    x.add_argument("--add-tag", action="append")
    x.add_argument("--remove-tag", action="append")
    x.add_argument("--hierarchy", action="append", help="hierarchy path(s); replaces all armorcode.group tags")
    x.add_argument("--type-id")
    x.add_argument("--team-id")
    x.add_argument("--owner", action="append", help="slot=userId, e.g. securityOwner=123")
    x.add_argument("--artifact", action="append", help="name=https://link")
    x = ps.add_parser("group-create")
    x.add_argument("--name", required=True)
    x.add_argument("--description")
    x.add_argument("--hierarchy", action="append")
    x.add_argument("--tag", action="append")
    x.add_argument("--tier")
    x.add_argument("--tier-tags", action="store_true")
    x.add_argument("--type-id")
    x = ps.add_parser("subgroup-create")
    x.add_argument("--group", required=True)
    x.add_argument("--name", required=True)
    x.add_argument("--description")
    x.add_argument("--tag", action="append")
    x = ps.add_parser("subgroup-update")
    x.add_argument("id")
    x.add_argument("--name")
    x.add_argument("--description")
    x.add_argument("--add-tag", action="append")
    x.add_argument("--remove-tag", action="append")
    x.add_argument("--hierarchy", action="append", help="place this subgroup on its own hierarchy path(s)")
    x = ps.add_parser("subgroup-move")
    x.add_argument("ids", nargs="+")
    x.add_argument("--to-group", required=True)
    for name in ("findings-update", "findings-move"):
        x = ps.add_parser(name)
        x.add_argument("--aql", help="AQL v2 selecting the findings (validated and counted first)")
        x.add_argument("--ids", nargs="+", help="explicit finding ids instead of --aql")
        x.add_argument("--note", help="reason stored on every finding (required)")
        x.add_argument("--max", type=int, help=f"change at most N findings, e.g. 20 for a pilot (cap {LARGE_BULK})")
        x.add_argument("--allow-large", action="store_true", help=f"allow more than {LARGE_BULK} findings")
        if name == "findings-update":
            x.add_argument("--status", help="OPEN, CONFIRMED, TRIAGE, IN_PROGRESS, CONTROLLED, FALSEPOSITIVE, "
                                            "SUPPRESSED, MITIGATED (ACCEPTRISK: use `plan exceptions`)")
            x.add_argument("--severity", help="CRITICAL, HIGH, MEDIUM, LOW, INFO")
        else:
            x.add_argument("--to-subgroup", required=True)
            x.add_argument("--env", default="Production")
    x = ps.add_parser("findings-revert", help="undo a findings-update plan using the values it captured")
    x.add_argument("plan_id")
    x.add_argument("--note")
    x = ps.add_parser("exceptions", help="one exception per group for the findings an AQL selects")
    x.add_argument("--aql", required=True, help="must include a status condition")
    x.add_argument("--name", required=True, help="name prefix; the group name is appended")
    x.add_argument("--reason", required=True, help="one of the tenant's exception reasons")
    x.add_argument("--end", required=True, help="end date YYYY-MM-DD (or full ISO time)")
    x.add_argument("--reviewer", action="append", required=True, help="reviewer user id, in approval order")
    x.add_argument("--description")
    x.add_argument("--approve-by")
    x.add_argument("--include-future", action="store_true", help="scope by the AQL (auto-adds later matches) "
                                                                "instead of today's finding ids")
    x.add_argument("--org", help="limit to one organization (business unit id, or 'pinned')")
    x.add_argument("--max", type=int)
    x.add_argument("--allow-large", action="store_true")
    x = ps.add_parser("exception-action", help="submit/approve/reject/archive exceptions")
    x.add_argument("action", choices=["submit", "approve", "reject", "archive"])
    x.add_argument("--ids", nargs="+", required=True)
    x.add_argument("--note", default="")
    x = ps.add_parser("scan-upload")
    x.add_argument("--tool", required=True, help="exact tool display name, e.g. 'Checkmarx One'")
    x.add_argument("--subgroup", required=True)
    x.add_argument("--file", required=True)
    x.add_argument("--env", default="Production")
    x.add_argument("--scan-date", help="ISO time, not in the future (default: now - 1h)")
    x = ps.add_parser("repo-map", help="map one repository, or many with --csv")
    x.add_argument("repo_id", nargs="?", help="repository id or exact name")
    x.add_argument("--subgroup")
    x.add_argument("--csv", help="CSV with columns repo,subgroup_id[,branch,environment]")
    x.add_argument("--env", default="Production")
    x.add_argument("--branch")
    x.add_argument("--code-scan", action="store_true")
    x.add_argument("--dependabot", action="store_true")
    x = ps.add_parser("team-members")
    x.add_argument("id")
    x.add_argument("--add", action="append", help="USER_ID:ROLE_NAME")
    x.add_argument("--remove", action="append", help="user id or email")
    x.add_argument("--accept-login-reset", action="store_true", help="proceed although members with disabled login exist")
    x = ps.add_parser("restore")
    x.add_argument("file")
    x = ps.add_parser("hierarchy-sync")
    x.add_argument("--desired", required=True, help="desired-state JSON (see hierarchy-export)")
    x.add_argument("--exact-tags", action="store_true", help="also remove group tags not in the file")
    x.add_argument("--move-misplaced", action="store_true", help="move subgroups found under another group")

    sp = sub.add_parser("plans", help="list plans, or show one with its results")
    sp.add_argument("id", nargs="?")
    sp.add_argument("--limit", type=int, default=20)
    sp = sub.add_parser("apply", help="execute a reviewed plan")
    sp.add_argument("plan_id")
    sp.add_argument("--confirm", required=True, help="the 6-character code printed with the plan")
    sp.add_argument("--allow-destructive", action="store_true")
    sp.add_argument("--allow-large", action="store_true")
    sp = sub.add_parser("backups", help="list recent backups")
    sp.add_argument("--limit", type=int, default=20)
    sp = sub.add_parser("audit", help="show changes applied from this machine")
    sp.add_argument("--tail", type=int, default=20)
    return ap


COMMANDS = {"ping": cmd_ping, "bus": cmd_bus, "get": cmd_get, "query": cmd_query, "groups": cmd_groups, "group": cmd_group,
            "subgroups": cmd_subgroups, "subgroup": cmd_subgroup, "hierarchy": cmd_hierarchy,
            "hierarchy-export": cmd_hierarchy_export, "teams": cmd_teams, "team": cmd_team, "users": cmd_users,
            "roles": cmd_roles, "findings": cmd_findings, "scans": cmd_scans, "repos": cmd_repos, "job": cmd_job,
            "spec": cmd_spec, "plan": cmd_plan, "apply": cmd_apply}
LOCAL_COMMANDS = {"plans": cmd_plans, "backups": cmd_backups, "audit": cmd_audit}


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.command == "profile":
            if args.action != "list" and not args.name:
                raise Refused("profile name is required")
            return cmd_profile(args)
        if args.command in LOCAL_COMMANDS:
            return LOCAL_COMMANDS[args.command](None, args)
        name, prof = select_profile(args)
        c = Client(name, prof)
        if args.command == "spec" and args.action == "show":
            args.method, args.path = args.term, args.path
        return COMMANDS[args.command](c, args)
    except Refused as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return EXIT_REFUSED
    except ApiError as e:
        print(f"API ERROR: {e}", file=sys.stderr)
        if e.status == 401:
            print("The API key was rejected: it may be expired, revoked, or for another tenant.", file=sys.stderr)
        elif e.status == 403:
            print("The key is valid but its role lacks permission for this call.", file=sys.stderr)
        return EXIT_API
    except KeyboardInterrupt:
        print("\nInterrupted. If an apply was running, re-run it to resume from the first unfinished step.",
              file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
