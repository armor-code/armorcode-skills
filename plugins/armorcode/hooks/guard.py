#!/usr/bin/env python3
"""PreToolUse guard for the ArmorCode plugin (Claude Code, Cowork, Codex, and agents that run Claude-format hooks).

Makes the agent ask the user before anything that changes an ArmorCode tenant runs, whatever the
model decided, and blocks the obvious ways of exposing the API key or tampering with ac.py's state:

  ask   `ac.py apply ...` (shows the plan's tenant, risk, steps and flags)
  ask   `ac.py profile add ... --mode read-write`
  ask   curl/wget/httpie/python requests that send writes to an ArmorCode host directly
  ask   ArmorCode MCP tools whose action is a write verb (update, upload, execute, ...)
  deny  edits to ~/.armorcode (profiles, plans, the plan-signing key) other than through ac.py
  deny  commands that would print a configured API key (env dumps, echo/cat of it, verbose curl, Keychain -w/-g)

Defense in depth, not a sandbox: ac.py itself refuses writes outside `apply`, and read-only profiles
refuse `apply`. On any internal error the hook stays silent, except that anything that looks like an
`apply` still gets an "ask".
"""
import json
import os
import re
import shlex
import sys
from pathlib import Path

HOME = Path(os.environ.get("ARMORCODE_HOME") or (Path.home() / ".armorcode")).expanduser()
PLAN_ID = re.compile(r"p-\d{8}-\d{6}-[0-9a-f]{4}")
WRITE_VERBS = {"update", "upload", "execute", "run", "add", "create", "delete", "remove", "set", "bulk", "propose",
               "start", "rescan", "assign", "mark", "close", "approve", "reject", "move", "archive", "comment"}


def decide(decision, reason):
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                             "permissionDecisionReason": reason}}))
    sys.exit(0)


def profiles():
    try:
        return json.loads((HOME / "profiles.json").read_text(encoding="utf-8")).get("profiles") or {}
    except (OSError, ValueError):
        return {}


def plan_summary(text):
    m = PLAN_ID.search(text)
    if not m:
        return "an ArmorCode change plan"
    pid = m.group(0)
    try:
        plan = json.loads((HOME / "plans" / f"{pid}.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return f"plan {pid} (file not found)"
    label = f" ({plan['label']})" if plan.get("label") else ""
    steps = plan.get("steps") or []
    lines = [f"plan {pid} on {plan.get('base_url')}{label}, risk {plan.get('risk')}, {len(steps)} step(s): "
             f"\"{plan.get('title')}\""]
    lines += [f"  - {s.get('summary') or s.get('kind')}" for s in steps[:5]]
    if len(steps) > 5:
        lines.append(f"  - ... and {len(steps) - 5} more")
    for w in (plan.get("warnings") or [])[:3]:
        lines.append(f"  ! {w[:160]}")
    return "\n".join(lines)


def tokens(cmd):
    try:
        return shlex.split(cmd, posix=True)
    except ValueError:
        return cmd.split()


def is_ac_apply(cmd):
    toks = tokens(cmd)
    for i, t in enumerate(toks):
        if t.endswith("ac.py") and "apply" in toks[i + 1:i + 4]:
            return True
    flat = re.sub(r"['\"\\]", "", cmd)          # defeats ap''ply / ap\ply style splitting
    if re.search(r"ac\.py\b(\s+--profile\s+\S+)?\s+apply\b", flat):
        return True
    return bool(re.search(r"\bac\b.*\bmain\s*\(.*apply", flat) or re.search(r"cmd_apply|EXECUTORS\[", flat))


def check_bash(cmd):
    profs = profiles()
    hosts = {re.sub(r"^https?://", "", p.get("base_url", "")).rstrip("/") for p in profs.values()}
    hosts = {h for h in hosts if h} | {"armorcode.com", "armorcode.ai", "armorcode.io"}
    token_envs = {p["token_env"] for p in profs.values() if p.get("token_env")} | {"ARMORCODE_TOKEN"}
    keychains = {p["token_keychain"] for p in profs.values() if p.get("token_keychain")}
    token_files = {str(Path(p["token_file"]).expanduser()) for p in profs.values() if p.get("token_file")}
    flat = re.sub(r"['\"\\]", "", cmd)

    # --- key exposure -------------------------------------------------------------------------
    if re.search(r"(^|[;&|(]\s*)(printenv|env|export\s+-p|declare\s+-x|set)\s*($|[;&|>)])", cmd):
        decide("deny", "Blocked: dumping the environment would expose API keys. Check a single variable with "
                       "`test -n \"$VAR\" && echo set`.")
    for var in token_envs:
        if re.search(rf"\b(echo|printf|print)\b[^;&|]*\$\{{?(?<!#){re.escape(var)}\b", cmd):
            decide("deny", f"Blocked: this would print the API key held in {var}. ac.py reads it itself.")
        if re.search(rf"printenv\s+{re.escape(var)}\b|environ(\.get)?\W+{re.escape(var)}", cmd) and \
                re.search(r"printenv|print|write|echo", cmd):
            decide("deny", f"Blocked: this would print the API key held in {var}.")
    if re.search(r"\b(curl|http|https|xh|wget)\b", cmd) and re.search(r"(^|\s)(-v|--verbose|--trace\S*|-vv+)\b", cmd) \
            and re.search(r"authorization|bearer", cmd, re.I):
        decide("deny", "Blocked: verbose HTTP output would print the Authorization header (the API key).")
    if "find-generic-password" in cmd and re.search(r"(^|\s)-[a-zA-Z]*[wg]\b", cmd) and \
            (not keychains or any(svc in cmd for svc in keychains) or "armorcode" in cmd.lower()):
        decide("deny", "Blocked: this would print an ArmorCode API key from the Keychain.")
    for tf in token_files:
        if tf in cmd or os.path.basename(tf) in flat:
            if re.search(r"\b(cat|less|more|head|tail|bat|strings|xxd|od|base64|cp|scp)\b", cmd):
                decide("deny", "Blocked: this would read or copy the ArmorCode API key file.")

    # --- tampering with ac.py state -------------------------------------------------------------
    home = str(HOME)
    # Redirections that only discard or merge output (2>/dev/null, 2>&1) don't write anything.
    quiet = re.sub(r"\d*>>?\s*(/dev/null|NUL)\b|\d*>&\d", " ", cmd)
    # `.armorcode` as a path segment (~/.armorcode/...), not as part of a hostname like www.armorcode.com.
    names_state = home in cmd or re.search(r"(?<![\w.-])\.armorcode(?=$|[/\\\s'\"])", cmd)
    if names_state and not re.search(r"ac\.py\b", cmd):
        if re.search(r"(sed\s+-i|>\s*\S|>>|\btee\b|\bmv\b|\bcp\b|\brm\b|\bchmod\b|open\(.*['\"][wa]|write_text|"
                     r"truncate|\bperl\s+-p?i)", quiet):
            decide("deny", "Blocked: ArmorCode profiles, plans and the plan-signing key may only be changed through "
                           "ac.py (e.g. `ac.py profile add`), so every change keeps its review trail.")

    # --- applying changes --------------------------------------------------------------------
    if is_ac_apply(cmd):
        decide("ask", "ArmorCode WRITE. This applies " + plan_summary(cmd) + "\nApprove only if this matches the "
                      "dry run you reviewed and you want this exact change made.")
    toks = tokens(cmd)
    if any(t.endswith("ac.py") for t in toks) and "profile" in toks and "add" in toks and "read-write" in toks:
        decide("ask", "ArmorCode: this creates a read-write profile, which allows reviewed plans to be applied to "
                      "that tenant (each still needs its own approval).")

    # --- direct writes bypassing ac.py -----------------------------------------------------------
    talks_to_ac = any(h in cmd for h in hosts)
    if talks_to_ac:
        http_cli = re.search(r"\b(curl|wget|http|https|xh)\b", cmd)
        cli_write = re.search(r"(-X|--request)\s*=?\s*['\"]?(POST|PUT|PATCH|DELETE)|--data\S*|(^|\s)-d\S*|--json|"
                              r"--upload-file|(^|\s)-T\s|(^|\s)-F\s|--form|\b(POST|PUT|PATCH|DELETE)\s+https?://",
                              cmd, re.I)
        code_write = re.search(r"(urlopen|requests\.|httpx\.|urllib)", cmd) and \
            re.search(r"\b(POST|PUT|PATCH|DELETE|post|put|patch|delete)\b", cmd)
        if (http_cli and cli_write) or code_write:
            decide("ask", "ArmorCode: this sends a request that may change the tenant directly, without ac.py's "
                          "plan, backup, verification and audit log. Approve only if you meant to bypass them.")


def check_edit(tool_input):
    path = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
    try:
        inside = Path(path).expanduser().resolve().is_relative_to(HOME.resolve())   # 3.9+
    except AttributeError:
        inside = str(Path(path).expanduser().resolve()).startswith(str(HOME.resolve()) + os.sep)
    except (OSError, ValueError):
        inside = False
    if inside:
        decide("deny", "Blocked: files under the ArmorCode state directory (profiles, plans, backups, the plan key) "
                       "may only be changed through ac.py.")


PATCH_FILE = re.compile(r"^\*\*\* (?:Add|Update|Delete) File: (.+?)\s*$|^\*\*\* Move to: (.+?)\s*$", re.M)


def check_patch(text):
    """Codex apply_patch: the patch text names every file it touches."""
    for m in PATCH_FILE.finditer(text or ""):
        check_edit({"file_path": m.group(1) or m.group(2)})


def check_mcp(tool):
    action = tool.split("__")[-1].lower()
    words = set(re.split(r"[_\-]+", action))
    if words & WRITE_VERBS:
        decide("ask", f"ArmorCode MCP tool '{action}' may change data in your tenant. Approve only if you reviewed "
                      "exactly what it will do.")


def main():
    if "--check-python" in sys.argv[1:]:          # used by run-guard.sh to pick a working interpreter
        sys.exit(0 if sys.version_info >= (3, 8) else 1)
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
        tool = data.get("tool_name", "")
        tin = data.get("tool_input") or {}
        if tool == "Bash":
            check_bash(tin.get("command", ""))
        elif tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
            if "*** Begin Patch" in str(tin.get("command") or ""):
                check_patch(tin.get("command"))      # Codex reports apply_patch as Edit/Write
            else:
                check_edit(tin)
        elif tool == "apply_patch":
            check_patch(tin.get("command") or tin.get("input") or "")
        elif tool.startswith("mcp__") and "armorcode" in tool.lower():
            check_mcp(tool)
    except SystemExit:
        raise
    except Exception:
        if re.search(r"ac\.py.*apply", raw):
            decide("ask", "ArmorCode WRITE: applying a change plan. Approve only if you reviewed it.")
    sys.exit(0)


if __name__ == "__main__":
    main()
