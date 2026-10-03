# Issue 跟踪器

工程技能的 Issue 目标是 `ZJPex/RepoSteward`。每次 GitHub 操作都显式传入
`--repo ZJPex/RepoSteward` 或对应 REST 路径，不依赖本地远端名称推断目标。
使用 Windows 主机的 `C:\Program Files\GitHub CLI\gh.exe`，先核对登录账号为 `ZJPex`。

读取 Issue 时获取正文、评论和标签；编号可能同时指 Issue 或 PR，应先辨别类型。
PR 不作为分诊请求入口。

创建 Issue 遵循根目录 `AGENTS.md` 的在线 Project 草稿、去重与安全审查、
审阅者策略和独立发布门禁；本配置不授权直接执行 `gh issue create`。
评论、标签和关闭等写入也需遵守当前任务的具体授权及账号核验。
