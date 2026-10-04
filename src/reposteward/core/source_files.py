"""精确源码例外仍执行的内容与普通文件边界。"""

import hashlib
import os
import stat
from pathlib import Path

SOURCE_SUFFIXES = frozenset(
    {
        ".py",
        ".pyi",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".go",
        ".rs",
        ".java",
        ".kt",
        ".kts",
        ".c",
        ".h",
        ".cpp",
        ".hpp",
        ".cc",
        ".cs",
        ".rb",
        ".php",
        ".swift",
        ".scala",
        ".vue",
        ".svelte",
        ".sh",
    }
)


def source_digest(root: Path, path: str) -> str:
    relative = Path(path)
    if relative.suffix.casefold() not in SOURCE_SUFFIXES:
        raise ValueError("源码例外仅支持具体源码文件。")
    source = root / relative
    if not source.parent.resolve().is_relative_to(root):
        raise ValueError("源码路径超出工作区。")
    current = source
    for _ in relative.parts:
        if current.is_symlink():
            raise ValueError("源码文件和父目录不能是符号链接。")
        current = current.parent
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 20_000_000:
            raise ValueError("源码必须是检查上限内的普通文件。")
        content = handle.read(20_000_001)
        after = os.fstat(handle.fileno())
    if len(content) > 20_000_000 or (info.st_ino, info.st_size, info.st_mtime_ns) != (
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise ValueError("源码检查期间发生变化。")
    if b"PRIVATE KEY-----" in content or b"PuTTY-User-Key-File-" in content:
        raise ValueError("私钥不能申请源码例外。")
    return hashlib.sha256(content).hexdigest()
