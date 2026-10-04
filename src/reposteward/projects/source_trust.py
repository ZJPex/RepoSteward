"""导入页面的候选证据与精确源码授权，不执行最终导入。"""

from __future__ import annotations

import uuid
from pathlib import Path

import tomlkit

from reposteward.core.config import (
    ConfigError,
    _tracked_sensitive_paths,
    source_trust_revisions,
)
from reposteward.core.source_files import SOURCE_SUFFIXES, source_digest
from reposteward.core.source_rules import exact_rule, matches_rule
from reposteward.core.trusted_config import ConfigTrustStore, sha
from reposteward.projects.registry import (
    ProjectError,
    local_git,
    normalize_remote,
    workspace_metadata,
)
from reposteward.storage.local_queue import digest
from reposteward.storage.snapshots import _entries
from reposteward.verification.verifier import DockerVerifier


def candidate(root: Path, path: str) -> dict:
    """仅检查单个已跟踪源码文件，证据不含文件内容。"""
    try:
        if path != path.strip() or any(ord(c) < 32 for c in path):
            raise ProjectError("请输入规范的仓库相对文件路径。")
        _tracked_sensitive_paths({"owner/repo": [path]})
        relative = Path(path)
        if (
            relative.as_posix() != path
            or relative.suffix.casefold() not in SOURCE_SUFFIXES
        ):
            raise ProjectError("仅允许具体源码文件，不能授权目录或凭据文件。")
        if DockerVerifier._environment_path(relative):
            raise ProjectError("环境凭据不能申请源码例外。")
        tracked = local_git(
            root, "ls-files", "--cached", "-z", "--", ":(literal)" + path
        ).split("\0")
        if tracked != [path, ""]:
            raise ProjectError("文件必须已由当前仓库精确跟踪。")
        DockerVerifier._validate_allowlisted_sensitive_source(root / path, relative)
        entries, _ = _entries(
            root, trusted_sensitive_paths=(exact_rule(path),), names={path: True}
        )
        if source_digest(root, path) != entries[0]["digest"]:
            raise ProjectError("文件检查期间发生变化，请重试。")
        again, _ = _entries(
            root, trusted_sensitive_paths=(exact_rule(path),), names={path: True}
        )
        if entries != again:
            raise ProjectError("文件检查期间发生变化，请重试。")
        return {
            "path": path,
            "valid": True,
            "evidence": digest(entries),
            "message": "已核验具体源码文件；尚未授权。",
        }
    except (ValueError, RuntimeError, OSError) as exc:
        return {
            "path": path,
            "valid": False,
            "message": str(exc)
            if isinstance(exc, ProjectError)
            else "候选不是合法且稳定的已跟踪源码文件。",
            "evidence": "",
        }


class SourceTrust:
    def __init__(self, operations):
        self.operations = operations

    def storage(self):
        config = self.operations.config
        paths = [Path(path) for layer, path in config.config_files if layer == "user"]
        if len(paths) != 1:
            raise ConfigError("源码授权需要明确加载的可信用户配置。")
        return ConfigTrustStore(paths[0], config.state_dir / "source-trust")

    def identity(self, import_id: str, target: str) -> dict:
        draft = self.operations.imports.draft(import_id)
        source = draft["source"]
        if source["kind"] == "local_path":
            if target and Path(target).resolve() != Path(source["value"]).resolve():
                raise ProjectError("信任目标必须是此次导入的原始本地目录。")
            target = source["value"]
        if not Path(target).is_absolute():
            raise ProjectError("请先选择已有 Git 目录。")
        meta = workspace_metadata(Path(target))
        if meta["host"] != self.operations.imports.host:
            raise ProjectError("仓库主机与当前账户不一致。")
        if source["kind"] == "local_path":
            identified = self.operations.imports.source_identity(import_id)
            if (
                meta != identified["workspace"]
                or meta["identity"] not in identified["remote"]["aliases"]
            ):
                raise ProjectError("本地仓库身份已变化，请重新识别项目。")
        if source["kind"] == "github_url":
            view = self.operations.imports.show(import_id)
            remote = (view.get("inspection") or {}).get("remote")
            aliases = (
                remote["aliases"]
                if remote
                else [normalize_remote(source["value"])["identity"]]
            )
            if meta["identity"] not in aliases:
                raise ProjectError("所选目录不是此次识别的仓库。")
        return {
            "workspace": meta,
            "source": source,
            "head": local_git(Path(meta["root"]), "rev-parse", "HEAD"),
        }

    def check(self, import_id: str, target: str, paths: list[str], key: str) -> dict:
        with self.operations.workbench.trust_lock:
            self.operations.workbench.check_configuration()
            storage = self.storage()
            request = digest({"import_id": import_id, "target": target, "paths": paths})
            identity = uuid.uuid5(
                uuid.NAMESPACE_URL, self.operations.account + ":trust-check:" + key
            ).hex
            with storage.locked():
                old = storage.get(identity)
                if old:
                    if old["request"] != request:
                        raise ProjectError("idempotency_conflict")
                    return old
                binding = self.identity(import_id, target)
                root = Path(binding["workspace"]["root"])
                items = [candidate(root, path) for path in dict.fromkeys(paths)]
                if self.identity(import_id, target) != binding:
                    raise ProjectError("工作区身份检查期间发生变化。")
                result = {
                    "id": identity,
                    "account_digest": self.operations.account,
                    "request": request,
                    "import_id": import_id,
                    "target": target,
                    "binding": binding,
                    "items": items,
                    "config_digest": sha(storage.read()),
                    "public_write": False,
                }
                result["digest"] = digest(result)
                storage.put(identity, request, result)
                return result

    def listing(self, import_id: str, target: str) -> dict:
        with self.operations.workbench.trust_lock:
            self.operations.workbench.check_configuration()
            binding = self.identity(import_id, target)
            repository = binding["workspace"]["repository"].casefold()
            safety = self.operations.config.safety
            exact = dict(safety.trusted_source_files).get(repository, ())
            legacy = dict(safety.tracked_sensitive_paths).get(repository, ())
            items = []
            for path in exact:
                coverage = [rule for rule in legacy if matches_rule(path, rule)]
                items.append(
                    {
                        "path": path,
                        "covering_rules": coverage,
                        "revocable": not coverage,
                    }
                )
            return {
                "repository": repository,
                "items": items,
                "legacy_rules": list(legacy),
            }

    def check_remove(
        self, import_id: str, target: str, paths: list[str], key: str
    ) -> dict:
        """撤销依据为配置精确项，无需文件仍存在或仍符合授权条件。"""
        with self.operations.workbench.trust_lock:
            self.operations.workbench.check_configuration()
            storage = self.storage()
            request = digest(
                {
                    "import_id": import_id,
                    "target": target,
                    "paths": paths,
                    "mode": "remove",
                }
            )
            identity = uuid.uuid5(
                uuid.NAMESPACE_URL,
                self.operations.account + ":trust-remove-check:" + key,
            ).hex
            with storage.locked():
                old = storage.get(identity)
                if old:
                    if old["request"] != request:
                        raise ProjectError("idempotency_conflict")
                    return old
                binding = self.identity(import_id, target)
                listed = {
                    item["path"]: item
                    for item in self.listing(import_id, target)["items"]
                }
                if (
                    not paths
                    or len(paths) != len(set(paths))
                    or any(not listed.get(path, {}).get("revocable") for path in paths)
                ):
                    raise ProjectError(
                        "只能撤销当前仓库未被目录规则覆盖的精确文件例外。"
                    )
                result = {
                    "id": identity,
                    "account_digest": self.operations.account,
                    "request": request,
                    "import_id": import_id,
                    "target": target,
                    "binding": binding,
                    "mode": "remove",
                    "items": [
                        {
                            "path": path,
                            "valid": True,
                            "evidence": "",
                            "message": "等待明确确认撤销。",
                        }
                        for path in paths
                    ],
                    "config_digest": sha(storage.read()),
                    "public_write": False,
                }
                result["digest"] = digest(result)
                storage.put(identity, request, result)
                return result

    def adopt(self, after: bytes):
        self.operations.workbench.adopt_source_trust(self.storage(), after)

    def save(
        self,
        import_id: str,
        check_id: str,
        expected_digest: str,
        paths: list[str],
        key: str,
        mode: str = "add",
    ) -> dict:
        if not paths or len(paths) != len(set(paths)):
            raise ProjectError("请明确选择不重复的具体文件。")
        operations = self.operations
        with operations.workbench.trust_lock:
            storage = self.storage()
            request = digest(
                {
                    "import_id": import_id,
                    "check_id": check_id,
                    "expected_digest": expected_digest,
                    "paths": paths,
                    "mode": mode,
                }
            )
            identity = uuid.uuid5(
                uuid.NAMESPACE_URL, operations.account + ":trust-save:" + key
            ).hex
            with storage.locked():
                storage.reconcile(storage.read())
                old = storage.get(identity)
                if old:
                    if old["request"] != request:
                        raise ProjectError("idempotency_conflict")
                    if old["saved"]:
                        if sha(storage.read()) == old["after_digest"]:
                            self.adopt(storage.read())
                        return old
                    current = storage.read()
                    if sha(current) == old["after_digest"]:
                        self.adopt(current)
                        old["saved"] = True
                        storage.put(identity, request, old)
                        return old
                    if sha(current) != old["before_digest"]:
                        raise ProjectError("配置已变化，请核对保存状态。")
                operations.workbench.check_configuration()
                checked = storage.get(check_id)
                if (
                    not checked
                    or checked.get("mode", "add") != mode
                    or checked.get("account_digest") != operations.account
                    or checked["import_id"] != import_id
                    or checked["digest"] != expected_digest
                    or digest(
                        {
                            name: value
                            for name, value in checked.items()
                            if name != "digest"
                        }
                    )
                    != expected_digest
                ):
                    raise ProjectError("候选检查依据已失效。")
                binding = self.identity(import_id, checked["target"])
                if binding != checked["binding"]:
                    raise ProjectError("工作区身份或提交已变化，请重新检查。")
                by_path = {item["path"]: item for item in checked["items"]}
                root = Path(binding["workspace"]["root"])
                for path in paths:
                    previous = by_path.get(path)
                    if mode == "remove":
                        listed = {
                            item["path"]: item
                            for item in self.listing(import_id, checked["target"])[
                                "items"
                            ]
                        }
                        if not previous or not listed.get(path, {}).get("revocable"):
                            raise ProjectError(
                                "撤销依据已变化，或文件仍由目录规则覆盖。"
                            )
                    elif (
                        not previous
                        or not previous["valid"]
                        or candidate(root, path) != previous
                    ):
                        raise ProjectError(
                            "选中文件已变化或不合法，整组未保存，请重新检查。"
                        )
                before = storage.read()
                if sha(before) != checked["config_digest"]:
                    raise ProjectError("配置已并发修改，请重新检查。")
                repository = binding["workspace"]["repository"]
                after = storage.render(before, repository, paths, mode)
                result = {
                    "id": identity,
                    "account_digest": self.operations.account,
                    "request": request,
                    "import_id": import_id,
                    "repository": repository,
                    "paths": paths,
                    "mode": mode,
                    "saved": False,
                    "before_digest": sha(before),
                    "after_digest": sha(after),
                    "after_revision": dict(
                        source_trust_revisions(
                            tomlkit.parse(after.decode("utf-8"))["safety"][
                                "source_trust_revisions"
                            ]
                        )
                    )[repository.casefold()],
                    "public_write": False,
                    "plan_generated": False,
                }
                storage.put(identity, request, result)
                operations.workbench.verify_other_config(storage.path)
                storage.replace(before, after)
                self.adopt(after)
                result["saved"] = True
                storage.put(identity, request, result)
                return result

    def status(self, request_id: str) -> dict:
        storage = self.storage()
        with storage.locked():
            storage.reconcile(storage.read())
            result = storage.get(request_id)
        if (
            not result
            or "saved" not in result
            or result.get("account_digest") != self.operations.account
        ):
            raise KeyError("源码授权保存记录不存在。")
        return result
