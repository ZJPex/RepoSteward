"""撤销精确授权的真实 HTTP 流程与旧计划失效验证。"""

import tomllib
from unittest.mock import patch

import test_source_trust_http

from reposteward.core.trusted_config import ConfigTrustStore


class RevokeSourceTrustHTTPTests(test_source_trust_http.SourceTrustHTTPTests):
    def grants(self, current):
        response = self.client.get(
            "/api/v1/source-trust",
            params={"import_id": current["id"], "target": str(self.repo)},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["data"]

    def revoke_check(self, current, paths=None, status=200):
        return self.command(
            "source-trust/revoke-check",
            {
                "import_id": current["id"],
                "target": str(self.repo),
                "paths": paths or [self.source],
            },
            status,
        )

    def revoke(self, current, checked, status=200):
        return self.command(
            "source-trust/revoke",
            {
                "import_id": current["id"],
                "check_id": checked["id"],
                "expected_digest": checked["digest"],
                "paths": [self.source],
            },
            status,
        )

    def test_two_entries_revoke_invalidates_plan_and_recheck_rejects(self):
        for local in (True, False):
            with self.subTest(local=local):
                current = self.inspect(
                    local=local, state="failed" if local else "completed"
                )
                self.saved(current, self.checked(current))
                fresh = self.inspect(local=local)
                preview = self.plan(fresh)
                self.assertEqual(self.grants(fresh)["items"][0]["path"], self.source)
                self.revoke(fresh, self.revoke_check(fresh))
                self.command(
                    "projects/apply",
                    {
                        "import_id": fresh["id"],
                        "preview_id": preview["id"],
                        "expected_digest": preview["digest"],
                    },
                    409,
                )
                if local:
                    self.inspect(state="failed")
                else:
                    self.plan(self.inspect(local=False), status=409)
                self.assert_unregistered()

    def test_queued_plan_cannot_apply_after_revoke(self):
        current = self.inspect(local=False)
        self.saved(current, self.checked(current))
        preview = self.plan(current)
        operation = self.command(
            "projects/apply",
            {
                "import_id": current["id"],
                "preview_id": preview["id"],
                "expected_digest": preview["digest"],
            },
        )
        self.revoke(current, self.revoke_check(current))
        self.operations.process_once()
        response = self.client.get(
            "/api/v1/operation",
            params={"operation_id": operation["id"]},
            headers=self.headers,
        )
        self.assertEqual(response.json()["data"]["state"], "failed")
        self.assert_unregistered()

    def test_deleted_file_can_be_revoked_and_other_rules_are_preserved(self):
        other = "src/secrets/other.py"
        self.add_source(other)
        self.user.write_text(
            self.user.read_text()
            + '\n# retain\n[safety.trusted_source_files]\n"other/repo" = ["src/secrets/other.py"]\n'
        )
        self.reload()
        current = self.inspect(local=False)
        self.saved(
            current, self.checked(current, [self.source, other]), [self.source, other]
        )
        (self.repo / self.source).unlink()
        self.revoke(current, self.revoke_check(current))
        rules = tomllib.loads(self.user.read_text())["safety"]["trusted_source_files"]
        self.assertEqual(rules["owner/repo"], [other])
        self.assertEqual(rules["other/repo"], [other])
        self.assertIn("# retain", self.user.read_text())
        self.assertEqual(
            [item["path"] for item in self.grants(current)["items"]], [other]
        )

    def test_directory_coverage_is_shown_and_cannot_be_revoked(self):
        self.write_user(["src/credentials"])
        self.reload()
        current = self.inspect(local=False)
        self.saved(current, self.checked(current))
        listing = self.grants(current)
        self.assertEqual(listing["items"][0]["covering_rules"], ["src/credentials"])
        self.assertFalse(listing["items"][0]["revocable"])
        before = self.user.read_bytes()
        self.revoke_check(current, status=409)
        self.revoke_check(current, ["src/credentials"], status=409)
        self.assertEqual(self.user.read_bytes(), before)

    def test_revoke_response_loss_replays_without_rewrite_and_failed_write_preserves(
        self,
    ):
        current = self.inspect(local=False)
        self.saved(current, self.checked(current))
        checked = self.revoke_check(current)
        before = self.user.read_bytes()
        with patch.object(
            ConfigTrustStore, "replace", side_effect=OSError("unavailable")
        ):
            self.revoke(current, checked, status=409)
        self.assertEqual(self.user.read_bytes(), before)
        body = {
            "import_id": current["id"],
            "check_id": checked["id"],
            "expected_digest": checked["digest"],
            "paths": [self.source],
        }
        headers = {**self.headers, "Idempotency-Key": "revoke-lost"}
        first = self.client.post(
            "/api/v1/commands/source-trust/revoke", json=body, headers=headers
        )
        self.assertEqual(first.status_code, 200, first.text)
        with patch.object(
            ConfigTrustStore, "replace", side_effect=AssertionError("no rewrite")
        ):
            again = self.client.post(
                "/api/v1/commands/source-trust/revoke", json=body, headers=headers
            )
        self.assertEqual(first.json()["data"], again.json()["data"])
        self.assertEqual(self.grants(current)["items"], [])

    def test_add_check_cannot_be_used_as_revoke_confirmation(self):
        current = self.inspect(local=False)
        checked = self.checked(current)
        self.saved(current, checked)
        self.revoke(current, checked, status=409)
        self.assertTrue(self.grants(current)["items"])

    def test_revoke_requires_local_session_origin_and_bound_confirmation(self):
        current = self.inspect(local=False)
        self.saved(current, self.checked(current))
        checked = self.revoke_check(current)
        before = self.user.read_bytes()
        body = {
            "import_id": current["id"],
            "check_id": checked["id"],
            "expected_digest": checked["digest"],
            "paths": [self.source],
        }
        for headers, status in (
            ({}, 401),
            (
                {
                    "Authorization": self.headers["Authorization"],
                    "Idempotency-Key": "no-origin",
                },
                403,
            ),
            (
                {
                    **self.headers,
                    "Origin": "https://example.invalid",
                    "Idempotency-Key": "other-origin",
                },
                403,
            ),
        ):
            response = self.client.post(
                "/api/v1/commands/source-trust/revoke", json=body, headers=headers
            )
            self.assertEqual(response.status_code, status, response.text)
        self.assertEqual(self.user.read_bytes(), before)

    def test_casefolded_legacy_prefix_cannot_mislead_single_file_revoke(self):
        self.write_user(["SRC/CREDENTIALS"])
        self.reload()
        current = self.inspect(local=False)
        self.saved(current, self.checked(current))
        item = self.grants(current)["items"][0]
        self.assertEqual(item["covering_rules"], ["SRC/CREDENTIALS"])
        self.assertFalse(item["revocable"])
        before = self.user.read_bytes()
        self.revoke_check(current, status=409)
        self.assertEqual(self.user.read_bytes(), before)
