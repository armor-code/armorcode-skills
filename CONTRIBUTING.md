# Contributing

Issues and pull requests are welcome. ArmorCode maintains this repository and reviews every change.

## Reporting a problem

Open an issue with the plugin version, your agent and OS, what you asked the agent, and what happened (the `ac.py` command and plan id help). Remove API keys, tenant URLs and tenant data first. Security issues go through [SECURITY.md](SECURITY.md) instead.

## Making a change

1. Edit under `plugins/armorcode/`. Prefer fixing the skill's references or `ac.py`'s helpers over adding new scripts.
2. Only document API behavior you have verified against a live, non-production tenant. Mark endpoints that aren't in ArmorCode's published API spec as **Internal, may change** in `references/endpoint-catalog.md`.
3. Keep examples fictional (Acme, Northwind). No customer names, people, hostnames, tenant ids or keys.
4. Run the checks:
   ```
   python3 tools/build.py --check
   python3 tests/test_cli.py
   python3 tests/test_guard.py
   actionlint                     # if you changed .github/workflows (brew install actionlint)
   ```
5. For a release, bump the version in `plugins/armorcode/.claude-plugin/plugin.json`, `plugins/armorcode/plugin.json`, `.claude-plugin/marketplace.json` (both places), the skill's `metadata.version` in `SKILL.md` and `VERSION` in `ac.py` (`tools/build.py --check` fails if they disagree), and add a `CHANGELOG.md` entry.

## Releasing (maintainers)

Merge to `main`, then push a tag that matches the version, e.g. `git tag v1.1.0 && git push origin v1.1.0`. The Release workflow tests, builds both zips, renders the getting-started PDF and publishes a GitHub Release with the CHANGELOG entry as notes. Claude Code users get the update from the marketplace; Desktop users download the new zip.

By contributing, you agree that your contribution is licensed under the [Apache License 2.0](LICENSE).
