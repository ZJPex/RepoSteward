"""有界的导入拒绝诊断；结果不授予信任，也不能替代快照校验。"""

import stat
import time
from pathlib import Path

from reposteward.projects.registry import ProjectError, local_git, workspace_state
from reposteward.projects.source_trust import candidate
from reposteward.storage import snapshots
from reposteward.verification.verifier import DockerVerifier

MAX_DIAGNOSTIC_ITEMS = 500
MAX_DIAGNOSTIC_SECONDS = 30


class ImportDiagnosticsError(ProjectError):
    def __init__(self, diagnostics: dict):
        super().__init__("导入检查未通过，请查看拒绝项。")
        self.diagnostics = diagnostics


def rule_coverage(name: str, rules: tuple[str, ...]) -> list[dict]:
    parts = tuple(part.casefold() for part in Path(name).parts)
    return [
        {
            "path": rule.removeprefix(":file:"),
            "kind": "file"
            if rule.startswith(":file:") or len(prefix) == len(parts)
            else "directory",
        }
        for rule in rules
        if (
            prefix := tuple(
                part.casefold() for part in rule.removeprefix(":file:").split("/")
            )
        )
        and (
            name == rule.removeprefix(":file:")
            if rule.startswith(":file:")
            else parts[: len(prefix)] == prefix
        )
    ]


def rejection(root: Path, name: str, tracked: bool, rules: tuple[str, ...]) -> dict:
    relative = Path(name)
    source = root / relative
    eligible = False
    code, message = "snapshot_rejected", "该路径未通过快照安全检查。"
    parents = [source, *list(source.parents)[: len(relative.parts) - 1]]
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or not source.parent.resolve().is_relative_to(root)
    ):
        code, message = "unsafe_path", "路径超出工作区或包含不支持的路径部分。"
    elif any(path.is_symlink() for path in parents):
        code, message = "symlink", "文件或父目录是符号链接，不能申请源码例外。"
    elif source.exists() and not source.is_file():
        code, message = "special_file", "目录、子模块或特殊文件不能按普通源码导入。"
    elif source.exists() and source.stat().st_size > snapshots.MAX_SNAPSHOT_FILE_BYTES:
        code, message = "byte_limit", "文件超出快照读取大小限制。"
    elif DockerVerifier._environment_path(relative):
        code, message = (
            "environment_file",
            "环境文件或模板未通过安全检查，不能申请源码例外。",
        )
    elif DockerVerifier._sensitive_path(relative):
        code, message = "sensitive_path", "已跟踪路径名称命中敏感文件规则。"
        if tracked:
            eligible = candidate(root, name)["valid"]
    return {
        "path": name,
        "reason": code,
        "message": message,
        "can_request_exception": eligible,
        "coverage": rule_coverage(name, rules),
    }


def diagnose(root: Path, rules: tuple[str, ...]) -> dict:
    started = time.monotonic()
    result = {
        "items": [],
        "complete": False,
        "checked_files": 0,
        "reason": "interrupted",
    }
    try:
        before = workspace_state(root)
        names = {
            name: True
            for name in local_git(root, "ls-files", "--cached", "-z").split("\0")
            if name
        }
        for name in local_git(
            root, "ls-files", "--others", "--exclude-standard", "-z"
        ).split("\0"):
            if name:
                names.setdefault(name, False)
        total = 0
        for name, tracked in sorted(names.items()):
            if (
                result["checked_files"] >= snapshots.MAX_SNAPSHOT_FILES
                or len(result["items"]) >= MAX_DIAGNOSTIC_ITEMS
                or time.monotonic() - started >= MAX_DIAGNOSTIC_SECONDS
            ):
                result["reason"] = "scan_limit"
                return result
            # 读取之前预留预算，失败文件也计入，避免反复失败绕过总读取上限。
            source = root / name
            try:
                metadata = source.lstat()
                size = metadata.st_size if stat.S_ISREG(metadata.st_mode) else 0
            except FileNotFoundError:
                size = 0
            if (
                size > snapshots.MAX_SNAPSHOT_FILE_BYTES
                or total + size > snapshots.MAX_SNAPSHOT_BYTES
            ):
                result["items"].append(rejection(root, name, tracked, rules))
                result["reason"] = "byte_limit"
                return result
            total += size
            try:
                snapshots._entries(
                    root, trusted_sensitive_paths=rules, names={name: tracked}
                )
            except (ProjectError, OSError):
                item = rejection(root, name, tracked, rules)
                result["items"].append(item)
                # 文件变化、读取失败与已放行源码的后续失败不能被当作完整检查。
                if item["reason"] in {"snapshot_rejected", "byte_limit"} or (
                    item["reason"] == "sensitive_path" and item["coverage"]
                ):
                    result["reason"] = "snapshot_interrupted"
                    return result
            result["checked_files"] += 1
        if workspace_state(root) != before:
            result["reason"] = "workspace_changed"
        elif result["items"]:
            result.update(complete=True, reason="completed")
    except (ProjectError, OSError):
        pass
    return result
