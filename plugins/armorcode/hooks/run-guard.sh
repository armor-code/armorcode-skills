#!/bin/sh
# Runs the ArmorCode approval hook (guard.py) with the first Python 3.8+ it finds.
# Windows installs Python as `python` or `py` rather than `python3`, so try all three.
# If none works, warn and let the tool call through: ac.py still refuses to send any
# change outside `ac.py apply`, so a missing hook never opens a write path.
# Every line ends in a comment so the script still runs if Git checked it out with CRLF.
for py in python3 python py; do #
  if command -v "$py" >/dev/null 2>&1 && #
     "$py" "${CLAUDE_PLUGIN_ROOT}/hooks/guard.py" --check-python </dev/null >/dev/null 2>&1; then #
    exec "$py" "${CLAUDE_PLUGIN_ROOT}/hooks/guard.py" #
  fi #
done #
echo "ArmorCode plugin: Python 3.8+ was not found, so its approval prompt is not running. Install Python 3 (see the README)." >&2 #
exit 1 #
