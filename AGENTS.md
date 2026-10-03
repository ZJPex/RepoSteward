# RepoSteward contributor guidance

## Scope

RepoSteward discovers public GitHub issues, prepares fixes in disposable clones, and
opens pull requests only after repository-specific gates and local human review.

## Commands

- Install: `uv sync`
- Tests: `uv run python -m unittest discover -s tests -v`
- Lint: `uvx ruff check .`
- Format check: `uvx ruff format --check .`
- CLI smoke test: `uv run reposteward --help`

## Safety invariants

- Every code change must start from a reviewed open Issue, use a separate branch or
  worktree, and be merged through a focused PR. Never commit or push code directly to
  `main`. Handle security emergencies through the private process in `SECURITY.md`.
- Scope each Issue and PR around one concrete, independently verifiable capability.
  RepoSteward does not use changed-line count to force one capability into artificial
  slices; change size remains review evidence, not the scope boundary. Keep unrelated
  capabilities separate and preserve every non-line safety gate.
- Never expose GitHub credentials to a coding harness, tests, repository hooks,
  Git push, or Docker containers. An API credential may be passed only to the
  GitHub REST client; Git clone/push uses the host's SSH key.
- Do not submit a PR without a separate `submit` invocation, the
  `REPOSTEWARD_ENABLE_SUBMIT=1` environment gate, and a `--reviewed-by` value
  matching the configured GitHub login.
- Respect repository contribution policies. Assignment/approval checks are hard
  gates, not ranking hints.
- Never automate security reports or mass comments. Repository Issue creation must
  pass through the configured online Project draft, a fresh duplicate/security
  review digest, the reviewer policy from trusted user configuration, and the
  separate promotion gate. Distinct review remains the default; self-review is
  allowed only when `issue_review.require_distinct_reviewer = false` is explicitly
  set in the user-owned configuration for a single-maintainer repository.
- Keep public-repository tests inside the hardened verifier container.
- Treat remote branch deletion as a separate terminal cleanup. Delete only an exact
  RepoSteward-managed same-repository head after its PR merged, the SHA is unchanged,
  and fresh checks show it is neither default, protected, active, shared, nor used by
  another open PR. Keep closed-unmerged and fork branches by default.

For Issue triage, implementation handoff, PR preparation, and CI/reviewer follow-up,
read `.agents/skills/reposteward-maintainer/SKILL.md`. The skill describes the human
workflow; the code-enforced safety invariants above remain authoritative.
For remote branch audits and explicitly authorized cleanup, read
`.agents/skills/reposteward-branch-cleanup/SKILL.md`.

## Fork 分支约定

- `main` 只快进同步原仓库 `upstream/main`，不承载个人修改。
- `custom` 是个人文档与功能的长期集成基线。日常代码改动仍遵守上面的 Issue、独立分支和聚焦 PR 要求，以 `custom` 为基线开发。
- 上游更新先进入 `main`，再将 `main` merge 到 `custom`；保留并解决两边的改动，不强制覆盖 `custom`。
- 向原仓库贡献功能时，从最新 `upstream/main` 创建 `contribute/<功能>`，只 cherry-pick 该功能相关提交，核对差异与验证结果后再提交上游 PR。

## Agent skills

### Issue tracker

工程技能使用 `ZJPex/RepoSteward` 的 GitHub Issues；所有操作显式指定目标仓库。详见 `docs/agents/issue-tracker.md`。

### Triage labels

分诊状态使用五个默认标签名称。详见 `docs/agents/triage-labels.md`。

### Domain docs

使用单一上下文布局；按需读取根目录 `CONTEXT.md` 与 `docs/adr/`。详见 `docs/agents/domain.md`。
