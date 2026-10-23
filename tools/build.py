#!/usr/bin/env python3
"""Validate the armorcode plugin and build the distributable skill zip.

    python3 tools/build.py            # validate + build dist/armorcode-api.zip
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
    versions = {plugin.get("version"), market["plugins"][0].get("version"),
                re.search(r'version:\s*"?([\d.]+)', text).group(1),
                re.search(r'VERSION = "([\d.]+)"', (SKILL / "scripts" / "ac.py").read_text()).group(1)}
    if len(versions) != 1:
        errors += fail(f"version mismatch across plugin.json, marketplace.json, SKILL.md, ac.py: {versions}")
    print(f"{'OK' if not errors else 'ERRORS'}  name={name} description={len(desc)} chars, "
          f"SKILL.md body={lines} lines, version={versions}")
    return errors


def build():
    DIST.mkdir(exist_ok=True)
    out = DIST / "armorcode-api.zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(SKILL.rglob("*")):
            if f.is_file() and not (set(f.parts) & EXCLUDE):
                z.write(f, Path("armorcode-api") / f.relative_to(SKILL))
    print(f"Built {out} ({out.stat().st_size:,} bytes)")


if __name__ == "__main__":
    errs = validate()
    if errs:
        sys.exit(1)
    if "--check" not in sys.argv:
        build()
