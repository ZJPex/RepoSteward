"""精确文件与旧目录规则共享的匹配和展示语义。"""

from pathlib import Path

_FILE_MARKER = ":file:"


def exact_rule(path: str) -> str:
    return _FILE_MARKER + path


def is_exact(rule: str) -> bool:
    return rule.startswith(_FILE_MARKER)


def rule_path(rule: str) -> str:
    return rule.removeprefix(_FILE_MARKER)


def matches_rule(path: str, rule: str) -> bool:
    if is_exact(rule):
        return path == rule_path(rule)
    parts = tuple(part.casefold() for part in Path(path).parts)
    prefix = tuple(part.casefold() for part in rule.split("/") if part)
    return bool(prefix) and parts[: len(prefix)] == prefix


def exact_covered(path: str, rules: tuple[str, ...]) -> bool:
    return exact_rule(path) in rules


def rule_coverage(path: str, rules: tuple[str, ...]) -> list[dict]:
    return [
        {
            "path": rule_path(rule),
            "kind": "file"
            if is_exact(rule) or len(Path(rule).parts) == len(Path(path).parts)
            else "directory",
        }
        for rule in rules
        if matches_rule(path, rule)
    ]
