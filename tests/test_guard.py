"""Decision tests for the ArmorCode PreToolUse guard. Offline; run: python3 tests/test_guard.py"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GUARD = ROOT / "plugins" / "armorcode" / "hooks" / "guard.py"
V = "ARMORCODE" + "_TOKEN"          # split so this file doesn't trip secret scanners
PID = "p-20261023-120000-abcd"


def main():
    with tempfile.TemporaryDirectory() as home:
        (Path(home) / "plans").mkdir()
        (Path(home) / "profiles.json").write_text(json.dumps({"profiles": {"prod": {
            "base_url": "https://app.armorcode.com", "token_env": V, "mode": "read-only"}}, "default": "prod"}))
        (Path(home) / "plans" / f"{PID}.json").write_text(json.dumps({
            "id": PID, "title": "Update group 'payments' (1)", "base_url": "https://app.armorcode.com",
            "label": "PRODUCTION", "risk": "MEDIUM", "steps": [{"summary": "Update group 'payments' (1)"}]}))
        cases = [
            ("Bash", f"python3 /x/scripts/ac.py apply {PID} --confirm abc123", "ask"),
            ("Bash", f"python3 /x/scripts/ac.py --profile prod apply {PID} --confirm abc123", "ask"),
            ("Bash", f"python3 /x/scripts/ac.py ap''ply {PID} --confirm abc123", "ask"),
            ("Bash", f"python3 -c \"import ac; ac.main(['apply','{PID}','--confirm','x'])\"", "ask"),
            ("Bash", "python3 /x/ac.py findings count --aql \"summary LIKE '%apply%'\"", "allow"),
            ("Bash", "python3 /x/ac.py plan group-update 1 --add-tag x", "allow"),
            ("Bash", f'test -n "${V}" && echo set', "allow"),
            ("Bash", "echo ${#" + V + "}", "allow"),
            ("Bash", "echo $" + V, "deny"),
            ("Bash", 'echo "token=${' + V + '}"', "deny"),
            ("Bash", "printenv", "deny"),
            ("Bash", "env | grep -i token", "deny"),
            ("Bash", "printenv " + V, "deny"),
            ("Bash", 'python3 -c "import os; print(os.environ[\'' + V + '\'])"', "deny"),
            ("Bash", 'curl -v -H "Authorization: Bearer $' + V + '" https://app.armorcode.com/x', "deny"),
            ("Bash", "security find-generic-password -s armorcode-prod -w", "deny"),
            ("Bash", 'security add-generic-password -s armorcode-prod -a "$USER" -w', "allow"),
            ("Bash", f"sed -i 's/read-only/read-write/' {home}/profiles.json", "deny"),
            ("Bash", f"cat {home}/profiles.json", "allow"),
            ("Write", f"{home}/profiles.json", "deny"),
            ("Edit", f"{home}/plans/{PID}.json", "deny"),
            ("Write", "/tmp/notes.md", "allow"),
            ("Bash", 'curl -s -X PUT -H "Authorization: Bearer $T" https://app.armorcode.com/user/product -d @b.json', "ask"),
            ("Bash", "curl -s --json @b.json https://app.armorcode.com/api/team", "ask"),
            ("Bash", 'curl -s https://app.armorcode.com/api/tenant/businessUnits -H "Authorization: Bearer $T"', "allow"),
            ("Bash", "python3 /x/ac.py profile add prod-rw --token-env X --mode read-write", "ask"),
            ("Bash", "python3 /x/ac.py profile add prod --token-env X", "allow"),
            ("Bash", "set -e; python3 /x/ac.py ping", "allow"),
            ("mcp__armorcode__update_findings", "", "ask"),
            ("mcp__armorcode__group_assets", "", "allow"),
            ("mcp__armorcode__action_list_findings", "", "allow"),
            ("mcp__armorcode__add_finding_comment", "", "ask"),
            ("mcp__ArmorCode__execute_runbook", "", "ask"),
        ]
        fails = 0
        for tool, arg, want in cases:
            ti = {"command": arg} if tool == "Bash" else ({"file_path": arg} if tool in ("Write", "Edit") else {})
            r = subprocess.run([sys.executable, str(GUARD)], input=json.dumps({"tool_name": tool, "tool_input": ti}),
                               capture_output=True, text=True, env={"ARMORCODE_HOME": home, "PATH": "/usr/bin:/bin"})
            out = r.stdout.strip()
            got = json.loads(out)["hookSpecificOutput"]["permissionDecision"] if out else "allow"
            fails += got != want
            print(f"{'ok ' if got == want else 'XX '} {got:<6} want={want:<6} {tool:<36} {arg[:70]}")
        print(f"{len(cases) - fails}/{len(cases)} passed")
        return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
