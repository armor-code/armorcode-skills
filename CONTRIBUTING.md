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

## Anthropic's plugin directory (maintainers)

The plugin is submitted from ArmorCode's Claude organization at [claude.ai/directory/manage](https://claude.ai/directory/manage) › **Submit new** › **Plugin bundle**, with:

- **Repository:** `armor-code/armorcode-skills`
- **Plugin path:** `plugins/armorcode`
- **Branch or tag:** `main`, with the GitHub push webhook, so each release merged to `main` is re-validated and published

`tools/build.py --check` covers the directory's offline rules (see the [pre-submission checklist](https://claude.com/docs/plugins/pre-submission-checklist)). Keep `plugins/armorcode/README.md`'s "What it runs, sends and stores" section accurate whenever `ac.py` or the hook gains a new destination, command or file: the directory's security scan rejects undisclosed behavior. Expect each version to be held for a reviewer, because the hook runs Python and the skill reads the API key from the user's environment.

By contributing, you agree that your contribution is licensed under the [Apache License 2.0](LICENSE).
