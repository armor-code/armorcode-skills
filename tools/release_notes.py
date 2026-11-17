#!/usr/bin/env python3
"""Print the release notes for one version: its CHANGELOG section plus install steps.

    python3 tools/release_notes.py 1.1.0
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = ROOT / "plugins" / "armorcode" / "CHANGELOG.md"

INSTALL = """
## Install

**Claude Code** (terminal, IDE or the Desktop app's Code tab):

```
/plugin marketplace add armor-code/armorcode-claude
/plugin install armorcode@armorcode
```

**Claude Desktop app, Cowork and chat:** download `armorcode-plugin-{v}.zip` below, then Customize > Plugins > Add > Upload plugin.

**Skill only, in chat:** upload `armorcode-api-skill-{v}.zip` under Customize > Skills.

The getting-started guide (PDF) is attached below.
"""


def section(version):
    text = CHANGELOG.read_text(encoding="utf-8")
    m = re.search(rf"^## {re.escape(version)}\b.*?$(.*?)(?=^## |\Z)", text, re.M | re.S)
    if not m:
        sys.exit(f"No CHANGELOG entry for {version}")
    return m.group(1).strip()


if __name__ == "__main__":
    v = sys.argv[1]
    print(section(v))
    print(INSTALL.format(v=v))
