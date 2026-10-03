from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

import test_project_import
from fastapi.testclient import TestClient
from test_projects import git, repository

from reposteward.core.config import load_config
from reposteward.github.client import ConditionalRead, GitHubReadError
from reposteward.tasks.local_operations import LocalOperations
from reposteward.web.api.app import LocalSession, create_app
from reposteward.web.workbench import Workbench


class ImportHTTPTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_project_import.ProjectImportTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.session = LocalSession("127.0.0.1:8123")
        with patch(
            "reposteward.web.api.app.LocalOperations",
            return_value=self.fixture.operations,
        ):
            self.app = create_app(
                self.fixture.operations.workbench,
                session=self.session,
                manage_local=True,
            )
        self.client = TestClient(
            self.app, base_url=self.session.origin, client=("127.0.0.1", 1234)
        )
        self.addCleanup(self.client.close)
        self.headers = {
            "Authorization": "Bearer " + self.session.token,
            "Origin": self.session.origin,
            "Idempotency-Key": "request",
        }

    def test_import_commands_require_origin_session_and_bound_queries(self):
        body = {"kind": "github_url", "value": "https://github.com/owner/repo"}
        self.assertEqual(
            self.client.post(
                "/api/v1/commands/projects/inspect", json=body
            ).status_code,
            401,
        )
        self.assertEqual(
            self.client.post(
                "/api/v1/commands/projects/inspect",
                json=body,
                headers={k: v for k, v in self.headers.items() if k != "Origin"},
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.get(
                "/api/v1/import?import_id=" + "a" * 32 + "&unknown=1",
                headers=self.headers,
            ).status_code,
            400,
        )
        self.assertFalse(self.fixture.operations.path.exists())

    def test_url_credentials_rejected_with_useful_error_and_no_state(self):
        response = self.client.post(
            "/api/v1/commands/projects/inspect",
            json={
                "kind": "github_url",
                "value": "https://secret@github.com/owner/repo",
            },
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["error"]["code"], "invalid_source")
        self.assertNotIn("secret", response.text)
        self.assertFalse(self.fixture.operations.path.exists())

    def test_import_dto_roundtrip_preview_apply_and_persistent_read(self):
        response = self.client.post(
            "/api/v1/commands/projects/inspect",
            json={"kind": "github_url", "value": "https://github.com/owner/repo"},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 202, response.text)
        self.assertIn("operation_id=", response.headers["Location"])
        operation = response.json()["data"]
        self.fixture.operations.process_once()
        current = self.client.get(
            "/api/v1/import?import_id=" + operation["import_id"], headers=self.headers
        ).json()["data"]
        response = self.client.post(
            "/api/v1/commands/projects/plan",
            json={
                "import_id": current["id"],
                "inspection_id": current["inspection_id"],
                "method": "watch",
                "purpose": "watch",
                "target": "",
            },
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200, response.text)
        preview = response.json()["data"]
        response = self.client.post(
            "/api/v1/commands/projects/apply",
            json={
                "import_id": current["id"],
                "preview_id": preview["id"],
                "expected_digest": preview["digest"],
            },
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 202, response.text)
        self.fixture.operations.process_once()
        response = self.client.get(
            "/api/v1/import?import_id=" + current["id"], headers=self.headers
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["data"]["operations"][0]["state"], "completed")


class ImportTrustedSourceHTTPTests(unittest.TestCase):
    source = "src/credentials/route.py"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = repository(self.root / "checkout")
        self.user = self.root / "user.toml"
        self.project = self.root / "project.toml"
        self.project.write_text("config_version = 1\n", encoding="utf-8")
        self.write_user()
        self.github = Mock()
        self.github.conditional_get.side_effect = lambda path, **kwargs: (
            ConditionalRead(
                {"login": "owner"}
                if path == "/user"
                else {
                    "id": 101,
                    "full_name": "owner/repo",
                    "fork": False,
                    "default_branch": "main",
                },
                "",
                False,
            )
        )
        self.serial = 0
        self.reload()
        self.add_source(self.source)

    def write_user(self, paths=(), repository_name="owner/repo"):
        text = 'config_version = 1\n[github]\nlogin = "owner"\n'
        if paths:
            text += (
                "[safety.tracked_sensitive_paths]\n"
                + json.dumps(repository_name)
                + " = "
                + json.dumps(list(paths))
                + "\n"
            )
        self.user.write_text(text, encoding="utf-8")

    def reload(self):
        config = replace(
            load_config(self.project, user_path=self.user),
            state_dir=self.root / "state",
        )
        self.operations = LocalOperations(
            Workbench(config), client_factory=lambda config: self.github
        )
        self.session = LocalSession("127.0.0.1:8123")
        self.client = TestClient(
            create_app(
                self.operations.workbench,
                session=self.session,
                manage_local=True,
                operations=self.operations,
            ),
            base_url=self.session.origin,
            client=("127.0.0.1", 1234),
        )
        self.addCleanup(self.client.close)
        self.headers = {
            "Authorization": "Bearer " + self.session.token,
            "Origin": self.session.origin,
        }

    def add_source(self, name, contents="value = 'fixture'\n"):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
        git(self.repo, "add", name)
        return path

    def command(self, action, body, status=202):
        self.serial += 1
        response = self.client.post(
            "/api/v1/commands/" + action,
            json=body,
            headers={**self.headers, "Idempotency-Key": str(self.serial)},
        )
        self.assertEqual(response.status_code, status, response.text)
        return response.json().get("data")

    def inspect(self, local=True, state="completed"):
        operation = self.command(
            "projects/inspect",
            {
                "kind": "local_path" if local else "github_url",
                "value": str(self.repo)
                if local
                else "https://github.com/Owner/Repo.git",
            },
        )
        self.assertTrue(self.operations.process_once())
        response = self.client.get(
            "/api/v1/import?import_id=" + operation["import_id"], headers=self.headers
        )
        self.assertEqual(response.status_code, 200, response.text)
        current = response.json()["data"]
        self.assertEqual(current["operations"][0]["state"], state)
        return current

    def plan(self, current, status=200, method="link"):
        return self.command(
            "projects/plan",
            {
                "import_id": current["id"],
                "inspection_id": current["inspection_id"],
                "method": method,
                "purpose": "maintain",
                "target": str(self.repo) if method == "link" else "",
            },
            status,
        )

    def apply(self, current, preview, state="completed"):
        operation = self.command(
            "projects/apply",
            {
                "import_id": current["id"],
                "preview_id": preview["id"],
                "expected_digest": preview["digest"],
            },
        )
        self.operations.process_once()
        response = self.client.get(
            "/api/v1/operation?operation_id=" + operation["id"], headers=self.headers
        )
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()["data"]
        self.assertEqual(result["state"], state)
        return result

    def allow(self, paths=None, repository_name="owner/repo"):
        self.write_user(paths or (self.source,), repository_name)
        self.reload()

    def assert_unregistered(self):
        self.assertEqual(self.operations.workbench.registry.list()["projects"], [])

    def test_default_denies_local_inspection_and_remote_link_plan(self):
        self.inspect(state="failed")
        self.plan(self.inspect(local=False), status=409)
        self.assert_unregistered()

    def test_both_sources_link_once_preserve_dirty_files_and_repeat_apply(self):
        self.allow(repository_name="OWNER/REPO")
        dirty = self.repo / self.source
        dirty.write_text("value = 'uncommitted'\n", encoding="utf-8")
        before = git(self.repo, "status", "--porcelain=v1")
        for local in (True, False):
            with self.subTest(local=local):
                current = self.inspect(local=local)
                preview = self.plan(current)
                result = self.apply(current, preview)
                repeated = self.apply(current, preview)
                self.assertEqual(result["id"], repeated["id"])
                self.assertEqual(dirty.read_text(), "value = 'uncommitted'\n")
                self.assertEqual(git(self.repo, "status", "--porcelain=v1"), before)
                projects = self.operations.workbench.projects()["projects"]
                self.assertEqual(len(projects), 1)
                self.assertEqual(projects[0]["repository"], "owner/repo")
                self.assertEqual(projects[0]["workspace_count"], 1)
                self.assertFalse(projects[0]["policy"]["enabled"])

    def test_exact_file_does_not_authorize_sibling(self):
        self.allow()
        self.add_source("src/credentials/other.py")
        self.inspect(state="failed")
        self.plan(self.inspect(local=False), status=409)
        self.assert_unregistered()

    def test_other_repository_and_mismatched_origin_cannot_borrow_exception(self):
        self.allow(repository_name="another/repo")
        self.inspect(state="failed")
        self.allow()
        current = self.inspect(local=False)
        git(self.repo, "remote", "set-url", "origin", "git@github.com:another/repo.git")
        self.plan(current, status=409)
        self.assert_unregistered()

    def test_origin_on_another_host_cannot_borrow_exception(self):
        self.allow()
        git(self.repo, "remote", "set-url", "origin", "git@other.test:owner/repo.git")
        self.inspect(state="failed")
        self.plan(self.inspect(local=False), status=409)
        self.assert_unregistered()

    def test_repository_configuration_cannot_grant_trust(self):
        self.project.write_text(
            "config_version = 1\n[safety.tracked_sensitive_paths]\n"
            '"owner/repo" = ["src/credentials/route.py"]\n',
            encoding="utf-8",
        )
        self.reload()
        self.inspect(state="failed")
        self.assert_unregistered()
        self.allow()
        current = self.inspect()
        self.apply(current, self.plan(current))

    def test_untracked_sensitive_file_stays_excluded_when_it_changes(self):
        self.allow()
        ignored = self.repo / "src/credentials/local.py"
        ignored.write_text("fixture = 1\n", encoding="utf-8")
        current = self.inspect()
        preview = self.plan(current)
        ignored.write_text("fixture = 2\n", encoding="utf-8")
        self.apply(current, preview)
        self.assertEqual(ignored.read_text(), "fixture = 2\n")

    def test_environment_file_stays_rejected_under_allowed_directory(self):
        self.allow(paths=("src/credentials",))
        self.add_source("src/credentials/.env", "EXAMPLE=fixture\n")
        self.inspect(state="failed")
        self.assert_unregistered()

    def test_supported_environment_template_keeps_placeholder_rules(self):
        self.allow()
        self.add_source(".env.example", "API_KEY=replace-with-example\n")
        current = self.inspect()
        self.apply(current, self.plan(current))

    def test_allowlisted_symlink_is_rejected(self):
        self.allow()
        path = self.repo / self.source
        path.unlink()
        path.symlink_to(self.repo / "source.txt")
        self.inspect(state="failed")
        self.assert_unregistered()

    def test_allowed_source_edit_invalidates_plan_without_overwriting_contents(self):
        self.allow()
        current = self.inspect()
        preview = self.plan(current)
        path = self.repo / self.source
        path.write_text("value = 'edited after preview'\n", encoding="utf-8")
        self.apply(current, preview, state="failed")
        self.assertEqual(path.read_text(), "value = 'edited after preview'\n")
        self.assert_unregistered()

    def test_revoked_exception_blocks_old_instance_reload_and_retry(self):
        self.allow()
        current = self.inspect()
        preview = self.plan(current)
        self.write_user()
        self.command(
            "projects/apply",
            {
                "import_id": current["id"],
                "preview_id": preview["id"],
                "expected_digest": preview["digest"],
            },
            status=409,
        )
        self.reload()
        result = self.apply(current, preview, state="failed")
        self.command(
            "operations/retry",
            {"operation_id": result["id"], "expected_revision": result["revision"]},
        )
        self.operations.process_once()
        result = self.operations.operation(result["id"])
        self.assertEqual(result["state"], "failed")
        self.assert_unregistered()

    def test_watch_needs_neither_local_snapshot_nor_execution_policy(self):
        current = self.inspect(local=False)
        self.apply(current, self.plan(current, method="watch"))
        projects = self.operations.workbench.projects()["projects"]
        self.assertEqual(len(projects), 1)
        self.assertEqual(projects[0]["workspace_count"], 0)
        self.assertFalse(projects[0]["policy"]["enabled"])

    def test_allowed_source_change_during_remote_read_invalidates_inspection(self):
        self.allow()
        original = self.github.conditional_get.side_effect

        def read(path, **kwargs):
            if path.startswith("/repos/"):
                (self.repo / self.source).write_text("value = 'changed'\n")
            return original(path, **kwargs)

        self.github.conditional_get.side_effect = read
        self.inspect(state="failed")
        self.assertEqual((self.repo / self.source).read_text(), "value = 'changed'\n")
        self.assert_unregistered()

    def test_browser_cannot_supply_trusted_paths(self):
        self.command(
            "projects/inspect",
            {
                "kind": "local_path",
                "value": str(self.repo),
                "trusted_sensitive_paths": [self.source],
            },
            status=400,
        )
        self.assert_unregistered()

    def test_renamed_remote_keeps_verified_origin_alias_for_both_sources(self):
        self.allow()

        def read(path, **kwargs):
            if path == "/user":
                return ConditionalRead({"login": "owner"}, "", False)
            if path == "/repos/owner/repo":
                raise GitHubReadError(
                    "repository_moved", redirect_path="/repositories/101"
                )
            return ConditionalRead(
                {
                    "id": 101,
                    "full_name": "owner/renamed",
                    "fork": False,
                    "default_branch": "main",
                },
                "",
                False,
            )

        self.github.conditional_get.side_effect = read
        for local in (True, False):
            with self.subTest(local=local):
                current = self.inspect(local=local)
                self.assertEqual(
                    current["inspection"]["remote"]["aliases"],
                    ["github.com/owner/renamed", "github.com/owner/repo"],
                )
                self.apply(current, self.plan(current))
                projects = self.operations.workbench.projects()["projects"]
                self.assertEqual(len(projects), 1)
                self.assertEqual(projects[0]["repository"], "owner/renamed")
                self.assertEqual(projects[0]["workspace_count"], 1)
                self.assertEqual(
                    git(self.repo, "remote", "get-url", "origin"),
                    "https://github.com/Owner/Repo.git",
                )
                self.assertEqual(
                    (self.repo / self.source).read_text(), "value = 'fixture'\n"
                )
