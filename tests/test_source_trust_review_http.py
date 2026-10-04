"""审查发现的授权历史、仓库绑定和中断恢复回归。"""

import tomllib
from unittest.mock import patch

import test_source_trust_revoke_http
from test_projects import git

from reposteward.core.trusted_config import ConfigTrustStore


class SourceTrustReviewHTTPTests(
    test_source_trust_revoke_http.RevokeSourceTrustHTTPTests
):
    def test_regrant_does_not_revive_old_or_queued_plan(self):
        current = self.inspect(local=False)
        self.saved(current, self.checked(current))
        preview = self.plan(current)
        body = {
            "import_id": current["id"],
            "preview_id": preview["id"],
            "expected_digest": preview["digest"],
        }
        operation = self.command("projects/apply", body)
        self.revoke(current, self.revoke_check(current))
        self.saved(current, self.checked(current))
        self.command("projects/apply", body, 409)
        self.operations.process_once()
        self.assertEqual(self.operations.operation(operation["id"])["state"], "failed")
        self.assert_unregistered()
        fresh = self.plan(current)
        self.assertNotEqual(
            preview["plan"]["trust_revision"], fresh["plan"]["trust_revision"]
        )

    def test_local_origin_change_requires_new_identification_after_failed_inspect(self):
        current = self.inspect(state="failed")
        git(self.repo, "remote", "set-url", "origin", "https://github.com/other/repo")
        before = self.user.read_bytes()
        self.command(
            "source-trust/check",
            {
                "import_id": current["id"],
                "target": str(self.repo),
                "paths": [self.source],
            },
            409,
        )
        self.assertEqual(self.user.read_bytes(), before)

    def test_local_origin_change_requires_new_identification_after_success(self):
        self.allow()
        current = self.inspect()
        git(self.repo, "remote", "set-url", "origin", "https://github.com/other/repo")
        self.command(
            "source-trust/check",
            {
                "import_id": current["id"],
                "target": str(self.repo),
                "paths": [self.source],
            },
            409,
        )

    def interrupted_save(self):
        current = self.inspect(local=False)
        checked = self.checked(current)
        original = ConfigTrustStore.put

        def interrupt_result(store, identity, request, body):
            if body.get("saved"):
                raise OSError("fixture result interruption")
            return original(store, identity, request, body)

        body = {
            "import_id": current["id"],
            "check_id": checked["id"],
            "expected_digest": checked["digest"],
            "paths": [self.source],
        }
        with patch.object(ConfigTrustStore, "put", interrupt_result):
            self.command("source-trust/save", body, 409)
        storage = self.operations.source_trust.storage()
        with storage.ledger() as db:
            rows = db.execute("SELECT id,body FROM requests").fetchall()
        import json

        request_id = next(
            row["id"] for row in rows if "saved" in json.loads(row["body"])
        )
        return current, request_id

    def test_restart_then_new_write_reconciles_previous_saved_result(self):
        current, request_id = self.interrupted_save()
        self.reload()
        self.add_source("src/credentials/additional.py")
        checked = self.checked(current, ["src/credentials/additional.py"])
        self.saved(current, checked, ["src/credentials/additional.py"])
        response = self.client.get(
            "/api/v1/source-trust-result",
            params={"request_id": request_id},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["data"]["saved"])

    def test_ambiguous_external_change_reports_unknown_not_failed(self):
        before = self.user.read_bytes()
        _, request_id = self.interrupted_save()
        self.user.write_bytes(before + b"\n# unrelated external rewrite\n")
        self.reload()
        response = self.client.get(
            "/api/v1/source-trust-result",
            params={"request_id": request_id},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIsNone(response.json()["data"]["saved"])
        self.assertEqual(response.json()["data"]["outcome"], "unknown")

    def test_revision_is_user_owned_and_persists_after_reload(self):
        self.project.write_text(
            'config_version = 1\n[safety.source_trust_revisions]\n"owner/repo" = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n'
        )
        self.reload()
        self.assertEqual(self.operations.config.safety.source_trust_revisions, ())
        current = self.inspect(local=False)
        self.saved(current, self.checked(current))
        revision = tomllib.loads(self.user.read_text())["safety"][
            "source_trust_revisions"
        ]["owner/repo"]
        self.reload()
        self.assertEqual(
            dict(self.operations.config.safety.source_trust_revisions)["owner/repo"],
            revision,
        )
