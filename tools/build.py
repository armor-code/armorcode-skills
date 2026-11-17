#!/usr/bin/env python3
"""Validate the armorcode plugin and build the distributable skill zip.

    python3 tools/build.py            # validate + build dist/armorcode-plugin-<ver>.zip and the skill zip
    python3 tools/build.py --check    # validate only

Checks: SKILL.md frontmatter against the open Agent Skills spec (only name, description, license,
compatibility, metadata, allowed-tools; name format; description <= 1024 chars; no XML tags),
SKILL.md body < 500 lines, every referenced file exists, scripts compile, plugin/marketplace JSON parse,
and plugin/marketplace/skill versions agree.
"""
import json
import py_compile
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugins" / "armorcode"
SKILL = PLUGIN / "skills" / "armorcode-api"
DIST = ROOT / "dist"
ALLOWED_KEYS = {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}
EXCLUDE = {".DS_Store", "__pycache__"}


def fail(msg):
    print(f"FAIL  {msg}")
    return 1


def frontmatter(text):
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    if not m:
        return None, text
    fm, body = m.group(1), text[m.end():]
    data, key = {}, None
    for line in fm.splitlines():
        if re.match(r"^[A-Za-z_-]+:", line):
            key, _, val = line.partition(":")
            data[key.strip()] = val.strip()
        elif key and line.startswith("  "):
            data[key] = (data[key] + " " + line.strip()).strip()
    return data, body


def validate():
    errors = 0
    text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    fm, body = frontmatter(text)
    if fm is None:
        return fail("SKILL.md has no frontmatter")
    for key, val in fm.items():
        if key != "metadata" and val and val[0] not in "\"'|>" and ": " in val:
            errors += fail(f"frontmatter '{key}' contains ': ' in an unquoted value, which is invalid YAML")
    extra = set(fm) - ALLOWED_KEYS
    if extra:
        errors += fail(f"frontmatter keys outside the open spec: {sorted(extra)}")
    name, desc = fm.get("name", ""), fm.get("description", "")
    if not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", name) or len(name) > 64 or name != SKILL.name:
        errors += fail(f"name '{name}' must be kebab-case, <= 64 chars and equal the folder name")
    if not desc or len(desc) > 1024:
        errors += fail(f"description length {len(desc)} (must be 1-1024)")
    if re.search(r"<[^>]+>", name + desc):
        errors += fail("name/description must not contain XML tags")
    if len(fm.get("compatibility", "")) > 500:
        errors += fail("compatibility longer than 500 chars")
    lines = body.count("\n")
    if lines >= 500:
        errors += fail(f"SKILL.md body is {lines} lines (keep < 500)")
    for ref in sorted(set(re.findall(r"`((?:references|scripts|assets)/[^`\s]+)`", text))):
        if not (SKILL / ref).exists():
            errors += fail(f"SKILL.md references missing file {ref}")
    for md in (SKILL / "references").glob("*.md"):
        t = md.read_text(encoding="utf-8")
        if t.count("\n") > 100 and "## Contents" not in t and md.name != "endpoint-catalog.md":
            errors += fail(f"{md.name} is over 100 lines without a Contents section")
        for ref in set(re.findall(r"`((?:references|assets)/[^`\s]+)`", t)):
            if not (SKILL / ref).exists():
                errors += fail(f"{md.name} references missing file {ref}")
    for py in [SKILL / "scripts" / "ac.py", PLUGIN / "hooks" / "guard.py", Path(__file__)]:
        try:
            py_compile.compile(str(py), doraise=True)
        except py_compile.PyCompileError as e:
            errors += fail(f"{py.name} does not compile: {e}")
    plugin = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text())
    market = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
    json.loads((PLUGIN / "hooks" / "hooks.json").read_text())
    # Agent Plugins 1.0 manifest (Codex, GitHub Copilot, VS Code and other conforming clients). Closed schema.
    ap = json.loads((PLUGIN / "plugin.json").read_text())
    ap_keys = {"$schema", "name", "version", "description", "author", "homepage", "repository", "license",
               "keywords", "extensions"}
    if ap.get("$schema") != "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json":
        errors += fail("plugins/armorcode/plugin.json: $schema must be the Agent Plugins 1.0.0 identifier")
    if set(ap) - ap_keys:
        errors += fail(f"plugins/armorcode/plugin.json: fields outside the Agent Plugins schema: {sorted(set(ap) - ap_keys)}")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9]|[-.](?![-.]))*[a-z0-9]|[a-z0-9]", ap.get("name", "")) or \
            ap.get("name") != plugin.get("name"):
        errors += fail("plugins/armorcode/plugin.json: name must match the Claude manifest and the spec's name rules")
    for k in ("description", "license", "repository", "homepage", "keywords"):
        if ap.get(k) != plugin.get(k):
            errors += fail(f"plugins/armorcode/plugin.json: '{k}' differs from .claude-plugin/plugin.json")
    codex = json.loads((ROOT / ".agents" / "plugins" / "marketplace.json").read_text())
    for entry in codex["plugins"]:
        if not (ROOT / entry["source"]["path"]).is_dir():
            errors += fail(f".agents/plugins/marketplace.json: {entry['source']['path']} does not exist")
    for path in json.loads((ROOT / "skills.sh.json").read_text())["paths"]:
        if not (ROOT / path / SKILL.name / "SKILL.md").exists():
            errors += fail(f"skills.sh.json: {path} does not contain {SKILL.name}/SKILL.md")
    versions = {plugin.get("version"), market["plugins"][0].get("version"), ap.get("version"),
                re.search(r'version:\s*"?([\d.]+)', text).group(1),
                re.search(r'VERSION = "([\d.]+)"', (SKILL / "scripts" / "ac.py").read_text()).group(1)}
    if len(versions) != 1:
        errors += fail(f"version mismatch across the plugin manifests, marketplace.json, SKILL.md, ac.py: {versions}")
    print(f"{'OK' if not errors else 'ERRORS'}  name={name} description={len(desc)} chars, "
          f"SKILL.md body={lines} lines, version={versions}")
    return errors


def build():
    DIST.mkdir(exist_ok=True)
    version = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text())["version"]

    # 1. The plugin, with .claude-plugin/plugin.json at the top level, which is what the Desktop app's
    #    Customize > Plugins > Upload plugin and an org admin's Upload plugin expect. It also carries a
    #    marketplace.json whose plugin source is "./", so the same unzipped folder can be added with
    #    `/plugin marketplace add <folder>` in Claude Code (terminal, IDE, Desktop Code tab).
    market = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
    market["plugins"][0]["source"] = "./"
    plugin_zip = DIST / f"armorcode-plugin-{version}.zip"
    with zipfile.ZipFile(plugin_zip, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(PLUGIN.rglob("*")):
            if f.is_file() and not (set(f.parts) & EXCLUDE):
                z.write(f, f.relative_to(PLUGIN))
        z.writestr(".claude-plugin/marketplace.json", json.dumps(market, indent=2) + "\n")
    print(f"Built {plugin_zip} ({plugin_zip.stat().st_size:,} bytes)")

    # 2. The skill on its own, for Customize > Skills upload in chat.
    skill_zip = DIST / f"armorcode-api-skill-{version}.zip"
    with zipfile.ZipFile(skill_zip, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(SKILL.rglob("*")):
            if f.is_file() and not (set(f.parts) & EXCLUDE):
                z.write(f, Path("armorcode-api") / f.relative_to(SKILL))
    print(f"Built {skill_zip} ({skill_zip.stat().st_size:,} bytes)")


if __name__ == "__main__":
    errs = validate()
    if errs:
        sys.exit(1)
    if "--check" not in sys.argv:
        build()
