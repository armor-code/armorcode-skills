"""Offline unit tests for ac.py's safety logic (no network). Run: python3 tests/test_cli.py"""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

TMP = tempfile.mkdtemp()
os.environ["ARMORCODE_HOME"] = TMP                      # must be set before importing ac
os.environ["AC_TEST_TOKEN"] = "test-token-value-1234567890"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "plugins" / "armorcode" / "skills" /
                       "armorcode-api" / "scripts"))
import ac  # noqa: E402

PROFILE = {"base_url": "https://app.armorcode.com", "token_env": "AC_TEST_TOKEN", "mode": "read-write"}


class WriteGate(unittest.TestCase):
    def test_writes_refused_outside_apply(self):
        c = ac.Client("t", PROFILE)
        for method, path in [("PUT", "/user/product"), ("DELETE", "/api/team/1"), ("POST", "/api/runbook/5/run-now"),
                             ("PATCH", "/v2/products/mass"), ("POST", "/api/risk-register")]:
            with self.assertRaises(ac.Refused):
                c.request(method, path, body={})

    def test_known_read_posts_pass_the_gate(self):
        self.assertTrue(ac.is_read_post("/api/findings?size=1000"))
        self.assertTrue(ac.is_read_post("/user/findings/findingStats/all"))
        self.assertFalse(ac.is_read_post("/user/tools/generic/configurations"))
        self.assertFalse(ac.is_read_post("/api/runbook/5/run-now"))

    def test_https_required(self):
        with self.assertRaises(ac.Refused):
            ac.Client("t", dict(PROFILE, base_url="http://app.armorcode.com"))

    def test_token_scrubbed(self):
        c = ac.Client("t", PROFILE)
        self.assertNotIn("test-token-value", c._scrub("error with test-token-value-1234567890 inside"))


class Plans(unittest.TestCase):
    def setUp(self):
        self.c = ac.Client("t", PROFILE)

    def make(self, risk="MEDIUM", flags=None):
        with redirect_stdout(io.StringIO()):
            return ac.new_plan(self.c, "t", [{"kind": "request", "method": "PUT", "path": "/x", "body": {}}],
                               risk, ["r"], flags=flags or {})

    def test_tamper_detected(self):
        plan = self.make(risk="CRITICAL", flags={"allow_large": True})
        for field, value in [("risk", "LOW"), ("flags", {}), ("created", "2099-01-01T00:00:00Z"),
                             ("steps", [{"kind": "request", "method": "DELETE", "path": "/y"}])]:
            edited = dict(plan, **{field: value})
            self.assertNotEqual(ac.plan_hash(edited), plan["hash"], field)

    def test_results_do_not_change_signature(self):
        plan = self.make()
        self.assertEqual(ac.plan_hash(dict(plan, results=[{"step": 1}], progress={"1": {}})), plan["hash"])

    def test_load_plan_only_by_id(self):
        with self.assertRaises(ac.Refused):
            ac.load_plan("/etc/passwd")
        with self.assertRaises(ac.Refused):
            ac.load_plan("../plans/p-20261023-120000-abcd")


class Filters(unittest.TestCase):
    def test_unknown_key_refused(self):
        with self.assertRaises(ac.Refused):
            ac.check_filters({"sevrity": ["High"]})

    def test_string_boolean_refused(self):
        with self.assertRaises(ac.Refused):
            ac.check_filters({"correlatedFindingExits": ["true"]})

    def test_valid(self):
        ac.check_filters({"severity": ["High"], "id_term": [1], "aqlQueryV2": ["x = 1"], "keyValue.team": ["a"]})


class Risk(unittest.TestCase):
    def test_classification(self):
        cases = [("DELETE", "/api/team/1", None, "CRITICAL"), ("POST", "/user/product/archive/1", None, "HIGH"),
                 ("PATCH", "/v2/products/mass", None, "HIGH"), ("POST", "/api/sub-product/bulk/move", None, "HIGH"),
                 ("PUT", "/api/runbook/4", None, "HIGH"), ("POST", "/user/tickets/jira/bulk", None, "HIGH"),
                 ("POST", "/user/product", None, "MEDIUM"), ("POST", "/api/v2/saved-search/findings", None, "MEDIUM"),
                 ("POST", "/user/product/1", {"delete": "true"}, "CRITICAL")]
        for m, p, params, want in cases:
            self.assertEqual(ac.classify_request(m, p, params)[0], want, (m, p))


class Merging(unittest.TestCase):
    def test_merge_tags_case_insensitive_and_hierarchy_swap(self):
        tags = ac.merge_tags(["armorcode.group:a/b", "Team:X"], add=["team:x", "new:1"],
                             replace_prefix="armorcode.group:", replace_with=["armorcode.group:c/d"])
        self.assertEqual(tags, ["Team:X", "armorcode.group:c/d", "new:1"])

    def test_group_patch_keeps_unrelated_fields(self):
        g = {"id": 1, "name": "g", "tier": "2", "description": "d", "status": "Active", "tags": ["a:1"]}
        out = ac.apply_group_patch(g, {"set": {"description": "new"}, "add_tags": ["b:2"]})
        self.assertEqual((out["tier"], out["status"], out["description"], out["tags"]), ("2", "Active", "new", ["a:1", "b:2"]))

    def test_subgroup_body_sends_own_tags_only(self):
        s = {"id": 9, "name": "s", "product": {"id": 1, "name": "g"}, "tags": ["own:1", "grp:1", "armorcode.repo.url:x"],
             "tagsMetaMap": {"PRODUCT": ["grp:1"], "SUB_PRODUCT": ["own:1"]}}
        self.assertEqual(ac.prepare_subgroup_body(s)["tags"], ["own:1"])
        s.pop("tagsMetaMap")
        s["tagsMetaMap"] = {"PRODUCT": ["grp:1"], "TOOL": [{"toolConfigId": 1, "tags": ["tool:1"]}]}
        s["tags"] = ["own:1", "grp:1", "tool:1", "armorcode.repo.url:x"]
        self.assertEqual(ac.own_subgroup_tags(s), ["own:1"])

    def test_team_body_preserves_scope_shape(self):
        t = {"id": 5, "name": "t", "members": [], "properties": [
            {"id": 7, "businessUnit": {"id": 42, "name": "Org"}, "productSubProductMap": [], "accessOnAllProduct": False,
             "groups": ["acme/.*"]}]}
        body = ac.team_request_body(t)
        self.assertEqual(body["properties"][0]["businessUnitId"], 42)
        self.assertEqual(body["properties"][0]["groups"], ["acme/.*"])
        self.assertEqual(ac.scope_signature(t), ac.scope_signature(dict(t, properties=[
            dict(body["properties"][0], businessUnit={"id": 42})])))


class Redaction(unittest.TestCase):
    def test_redacts_secret_fields(self):
        out = ac.redact({"apiKey": "abcdefghijk", "password": "hunter2hunter2", "paginationToken": "keepmekeepme",
                         "nested": [{"clientSecret": "zzzzzzzzzz"}]})
        self.assertEqual(out["apiKey"], "***redacted***")
        self.assertEqual(out["paginationToken"], "keepmekeepme")
        self.assertEqual(out["nested"][0]["clientSecret"], "***redacted***")


class TokenSources(unittest.TestCase):
    def _file(self, mode):
        p = Path(TMP) / f"key-{mode:o}.txt"
        p.write_text("file-token-value-1234567890\n", encoding="utf-8")
        os.chmod(p, mode)
        return {"token_file": str(p)}

    @unittest.skipIf(os.name == "nt", "POSIX permission bits")
    def test_group_readable_file_refused_on_posix(self):
        with self.assertRaises(ac.Refused):
            ac.resolve_token(self._file(0o644))
        self.assertEqual(ac.resolve_token(self._file(0o600)), "file-token-value-1234567890")

    def test_permission_bits_ignored_on_windows(self):
        prof = self._file(0o644)
        saved, ac.IS_WINDOWS = ac.IS_WINDOWS, True
        try:
            self.assertEqual(ac.resolve_token(prof), "file-token-value-1234567890")
        finally:
            ac.IS_WINDOWS = saved

    def test_keychain_refused_off_macos(self):
        saved, ac.sys.platform = ac.sys.platform, "win32"
        try:
            with self.assertRaises(ac.Refused) as cm:
                ac.resolve_token({"token_keychain": "armorcode-prod"})
            self.assertIn("--token-env", str(cm.exception))
        finally:
            ac.sys.platform = saved


if __name__ == "__main__":
    unittest.main(verbosity=1)
