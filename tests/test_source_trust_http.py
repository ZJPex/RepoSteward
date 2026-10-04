"""真实临时 Git、用户配置与 HTTP 边界的精确授权测试。"""

import tomllib
from unittest.mock import patch

from test_import_http import ImportTrustedSourceHTTPTests

from reposteward.core.trusted_config import ConfigTrustStore


class SourceTrustHTTPTests(ImportTrustedSourceHTTPTests):
    def test_command_boundary_and_result_account_scope(self):
        current = self.inspect(local=False)
        body = {
            "import_id": current["id"],
            "target": str(self.repo),
            "paths": [self.source],
        }
        route = "/api/v1/commands/source-trust/check"
        response = self.client.post(route, json=body)
        self.assertEqual(response.status_code, 401)
        response = self.client.post(
            route,
            json=body,
            headers={
                **self.headers,
                "Origin": "https://example.org",
                "Idempotency-Key": "bad-origin",
            },
        )
        self.assertEqual(response.status_code, 403)
        checked = self.checked(current)
        result = self.saved(current, checked)
        self.operations.account = "different-account"
        response = self.client.get(
            "/api/v1/source-trust-result",
            params={"request_id": result["id"]},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 404)
        config = self.operations.config
        self.assertEqual(config.github.login, "owner")

    def test_other_config_change_during_save_is_not_adopted(self):
        current = self.inspect(local=False)
        checked = self.checked(current)
        original = ConfigTrustStore.replace

        def change_project(store, before, after):
            original(store, before, after)
            self.project.write_text('config_version = 1\n[agent]\nmodel = "changed"\n')

        with patch.object(ConfigTrustStore, "replace", change_project):
            self.saved(current, checked, status=409)
        response = self.client.get(
            "/api/v1/import", params={"import_id": current["id"]}, headers=self.headers
        )
        self.assertEqual(response.status_code, 409)

    def test_queued_old_plan_cannot_execute_after_trust_change(self):
        self.allow()
        current = self.inspect(local=False)
        preview = self.plan(current)
        operation = self.command(
            "projects/apply",
            {
                "import_id": current["id"],
                "preview_id": preview["id"],
                "expected_digest": preview["digest"],
            },
        )
        self.saved(current, self.checked(current))
        self.assertTrue(self.operations.process_once())
        self.assertEqual(self.operations.operation(operation["id"])["state"], "failed")
        self.assert_unregistered()

    def checked(self, current, paths=None):
        return self.command(
            "source-trust/check",
            {
                "import_id": current["id"],
                "target": str(self.repo),
                "paths": paths or [self.source],
            },
            200,
        )

    def saved(self, current, checked, paths=None, status=200):
        return self.command(
            "source-trust/save",
            {
                "import_id": current["id"],
                "check_id": checked["id"],
                "expected_digest": checked["digest"],
                "paths": paths or [self.source],
            },
            status,
        )

    def test_selective_save_preserves_toml_and_same_workbench_rechecks(self):
        for local in (True, False):
            with self.subTest(local=local):
                self.write_user()
                original = (
                    self.user.read_text()
                    + "\n# 保留无关格式\n[custom]\nanswer = 42 # 注释\n"
                )
                self.user.write_text(original)
                self.reload()
                current = self.inspect(
                    local=local, state="failed" if local else "completed"
                )
                self.add_source("src/secrets/other.py")
                checked = self.checked(
                    current, [self.source, "src/secrets/other.py", "../secrets/key.py"]
                )
                self.assertFalse(checked["items"][-1]["valid"])
                self.assertEqual(self.user.read_text(), original)
                result = self.saved(current, checked)
                self.assertTrue(result["saved"])
                content = self.user.read_text()
                self.assertIn("[custom]\nanswer = 42 # 注释", content)
                self.assertEqual(
                    tomllib.loads(content)["safety"]["trusted_source_files"][
                        "owner/repo"
                    ],
                    [self.source],
                )
                self.assertFalse(self.operations.workbench.registry.path.exists())
                checked = self.checked(current, ["src/secrets/other.py"])
                self.saved(current, checked, ["src/secrets/other.py"])
                fresh = self.inspect(local=local)
                plan = self.plan(fresh)
                self.assertIn("trust_revision", plan["plan"])
                self.assertFalse(self.operations.workbench.registry.path.exists())

    def test_selected_change_prevents_entire_save(self):
        self.add_source("src/secrets/second.py")
        current = self.inspect(local=False)
        checked = self.checked(current, [self.source, "src/secrets/second.py"])
        before = self.user.read_bytes()
        (self.repo / self.source).write_text("changed = True\n")
        self.saved(current, checked, [self.source, "src/secrets/second.py"], status=409)
        self.assertEqual(self.user.read_bytes(), before)

    def test_illegal_candidates_do_not_authorize(self):
        self.add_source("src/secrets/key.py", "-----BEGIN PRIVATE KEY-----\n")
        self.add_source("src/secrets/.env")
        (self.repo / "src/secrets/untracked.py").write_text("value = 1\n")
        (self.repo / "src/secrets/link.py").symlink_to(self.repo / self.source)
        from test_projects import git

        git(self.repo, "add", "src/secrets/link.py")
        current = self.inspect(local=False)
        checked = self.checked(
            current,
            [
                "src/secrets",
                "src/secrets/key.py",
                "src/secrets/.env",
                "src/secrets/untracked.py",
                "src/secrets/link.py",
            ],
        )
        self.assertTrue(all(not item["valid"] for item in checked["items"]))

    def test_write_failure_and_changed_config_preserve_original(self):
        current = self.inspect(local=False)
        checked = self.checked(current)
        before = self.user.read_bytes()
        with patch.object(
            ConfigTrustStore, "replace", side_effect=OSError("fixture write failure")
        ):
            self.saved(current, checked, status=409)
        self.assertEqual(self.user.read_bytes(), before)
        self.user.write_bytes(before + b"\n# concurrent edit\n")
        self.saved(current, checked, status=409)
        self.assertEqual(self.user.read_bytes(), before + b"\n# concurrent edit\n")

    def test_lost_response_replays_and_queries_persistent_result(self):
        current = self.inspect(local=False)
        checked = self.checked(current)
        body = {
            "import_id": current["id"],
            "check_id": checked["id"],
            "expected_digest": checked["digest"],
            "paths": [self.source],
        }
        headers = {**self.headers, "Idempotency-Key": "lost-response"}
        result = self.client.post(
            "/api/v1/commands/source-trust/save", json=body, headers=headers
        )
        self.assertEqual(result.status_code, 200, result.text)
        before = self.user.read_bytes()
        repeated = self.client.post(
            "/api/v1/commands/source-trust/save", json=body, headers=headers
        )
        self.assertEqual(result.json()["data"], repeated.json()["data"])
        self.assertEqual(self.user.read_bytes(), before)
        self.reload()
        result = self.client.get(
            "/api/v1/source-trust-result",
            params={"request_id": result.json()["data"]["id"]},
            headers=self.headers,
        )
        self.assertTrue(result.json()["data"]["saved"])

    def test_interrupted_record_after_replace_recovers_without_second_write(self):
        current = self.inspect(local=False)
        checked = self.checked(current)
        original = ConfigTrustStore.put

        def fail_result(store, identity, request, body):
            if body.get("saved"):
                raise OSError("lost result commit")
            return original(store, identity, request, body)

        body = {
            "import_id": current["id"],
            "check_id": checked["id"],
            "expected_digest": checked["digest"],
            "paths": [self.source],
        }
        headers = {**self.headers, "Idempotency-Key": "interrupted"}
        with patch.object(ConfigTrustStore, "put", fail_result):
            response = self.client.post(
                "/api/v1/commands/source-trust/save", json=body, headers=headers
            )
        self.assertEqual(response.status_code, 409)
        before = self.user.read_bytes()
        with patch.object(
            ConfigTrustStore, "replace", side_effect=AssertionError("must not rewrite")
        ):
            response = self.client.post(
                "/api/v1/commands/source-trust/save", json=body, headers=headers
            )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["data"]["saved"])
        self.assertEqual(self.user.read_bytes(), before)

    def test_exact_file_rule_does_not_cover_future_descendants(self):
        from test_projects import git

        current = self.inspect(local=False)
        self.saved(current, self.checked(current))
        (self.repo / self.source).write_text("normal_edit = True\n")
        self.plan(self.inspect(local=False))
        (self.repo / self.source).unlink()
        git(self.repo, "rm", "--cached", self.source)
        self.add_source(self.source + "/nested.py")
        self.plan(self.inspect(local=False), status=409)
