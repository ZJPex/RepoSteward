"""仅编辑用户级精确源码授权，保留原始 TOML 和可恢复写入凭据。"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import sqlite3
import stat
import tempfile
import uuid
from contextlib import contextmanager
from pathlib import Path

import tomlkit

from reposteward.core.config import (
    ConfigError,
    _tracked_sensitive_paths,
    source_trust_revisions,
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ConfigTrustStore:
    def __init__(self, path: Path, state: Path):
        self.path, self.state = path, state

    @contextmanager
    def locked(self):
        self.state.mkdir(parents=True, exist_ok=True)
        fd = os.open(
            self.path.with_name("." + self.path.name + ".source-trust.lock"),
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(fd, "r+") as handle:
            info = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_mode & 0o022
            ):
                raise ConfigError("源码授权锁权限不安全。")
            fcntl.flock(handle, fcntl.LOCK_EX)
            yield

    @contextmanager
    def ledger(self):
        self.state.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.state / "trust.sqlite3")
        db.row_factory = sqlite3.Row
        try:
            db.execute(
                "CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, request TEXT NOT NULL, body TEXT NOT NULL)"
            )
            yield db
            db.commit()
        finally:
            db.close()

    def read(self) -> bytes:
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 2_000_000:
                raise ConfigError("用户配置不是受支持的普通文件。")
            return handle.read(2_000_001)

    def get(self, identity: str) -> dict | None:
        if not (self.state / "trust.sqlite3").exists():
            return None
        with self.ledger() as db:
            row = db.execute(
                "SELECT body FROM requests WHERE id=?", (identity,)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, identity: str, request: str, body: dict):
        with self.ledger() as db:
            old = db.execute(
                "SELECT request FROM requests WHERE id=?", (identity,)
            ).fetchone()
            if old and old[0] != request:
                raise ConfigError("idempotency_conflict")
            db.execute(
                "INSERT OR REPLACE INTO requests VALUES (?,?,?)",
                (identity, request, json.dumps(body)),
            )

    def reconcile(self, current: bytes):
        """新写入前先固化未完成结果，无法判定的状态不伪装成失败。"""
        current_hash = sha(current)
        revisions = dict(
            source_trust_revisions(
                tomlkit.parse(current.decode("utf-8"))
                .get("safety", {})
                .get("source_trust_revisions", {})
            )
        )
        with self.ledger() as db:
            rows = db.execute("SELECT id,body FROM requests").fetchall()
            for row in rows:
                body = json.loads(row["body"])
                if "saved" not in body or body["saved"] is True:
                    continue
                after_revision = body.get("after_revision")
                revision_matches = (
                    after_revision
                    and revisions.get(body["repository"].casefold()) == after_revision
                )
                if current_hash == body["after_digest"] or revision_matches:
                    body.update(saved=True, outcome="saved")
                else:
                    body.update(saved=None, outcome="unknown")
                db.execute(
                    "UPDATE requests SET body=? WHERE id=?",
                    (json.dumps(body), row["id"]),
                )

    def render(
        self, before: bytes, repository: str, paths: list[str], mode: str
    ) -> bytes:
        document = tomlkit.parse(before.decode("utf-8"))
        safety = document.setdefault("safety", tomlkit.table())
        rules = safety.setdefault("trusted_source_files", tomlkit.table())
        existing = next(
            (name for name in rules if name.casefold() == repository.casefold()),
            repository.casefold(),
        )
        values = list(rules.get(existing, []))
        if mode == "add":
            values = list(dict.fromkeys([*values, *paths]))
        elif mode == "remove":
            if not set(paths).issubset(values):
                raise ConfigError("源码授权已变化，请刷新列表。")
            values = [path for path in values if path not in paths]
        else:
            raise ConfigError("未知源码授权动作。")
        if values:
            rules[existing] = values
        elif existing in rules:
            del rules[existing]
        _tracked_sensitive_paths(dict(rules))
        revisions = safety.setdefault("source_trust_revisions", tomlkit.table())
        revision_key = next(
            (name for name in revisions if name.casefold() == repository.casefold()),
            repository.casefold(),
        )
        revisions[revision_key] = uuid.uuid4().hex
        return tomlkit.dumps(document).encode("utf-8")

    def replace(self, before: bytes, after: bytes):
        """外部编辑器不共享锁；替换前核验摘要，替换后核验真实落盘值。"""
        original = self.path.lstat()
        if self.read() != before:
            raise ConfigError("用户配置已并发修改，请重新检查。")
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=self.path.parent, prefix=".source-trust-", delete=False
            ) as handle:
                temporary = Path(handle.name)
                os.fchmod(handle.fileno(), stat.S_IMODE(original.st_mode))
                handle.write(after)
                handle.flush()
                os.fsync(handle.fileno())
            current = self.path.lstat()
            if (current.st_dev, current.st_ino, current.st_mtime_ns) != (
                original.st_dev,
                original.st_ino,
                original.st_mtime_ns,
            ) or self.read() != before:
                raise ConfigError("用户配置已并发修改，请重新检查。")
            os.replace(temporary, self.path)
            parent = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
            if self.read() != after:
                raise ConfigError("保存后配置再次变化，请核对真实授权状态。")
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
