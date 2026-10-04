import { useRef, useState } from "react";
import { command, useRead } from "../api/client";
import { ImportFeedback } from "./import-feedback";

type Candidate = { path: string; valid: boolean; evidence: string; message: string };
type Checked = { id: string; digest: string; items: Candidate[] };
type SaveBody = { import_id: string; check_id: string; expected_digest: string; paths: string[] };
type Pending = { action: "source-trust/save" | "source-trust/revoke"; body: SaveBody };
type Grant = { path: string; covering_rules: string[]; revocable: boolean };
function remembered(key: string): Pending | null {
  try { return JSON.parse(sessionStorage.getItem(key) || "null") as Pending | null; }
  catch { return null; }
}

export function SourceTrustPanel({ importId, target, rejectedPaths, canManage, onSaved }: {
  importId: string; target: string; rejectedPaths: string[]; canManage: boolean;
  onSaved: () => Promise<void>;
}) {
  const storageKey = `reposteward-trust-pending:${importId}:${target}`;
  const [input, setInput] = useState("");
  const [checked, setChecked] = useState<Checked | null>(null);
  const [selected, setSelected] = useState<string[]>([]);
  const [pending, setPending] = useState<Pending | null>(() => remembered(storageKey));
  const [revoke, setRevoke] = useState<string | null>(null);
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const [savedMessage, setSavedMessage] = useState("");
  const [planFailed, setPlanFailed] = useState(false);
  const guard = useRef(false);
  const grants = useRead("source-trust", { import_id: importId, target }, Boolean(importId));
  const items = (grants.data?.items || []) as Grant[];
  const legacy = (grants.data?.legacy_rules || []) as string[];
  const disabled = !canManage || Boolean(busy);
  function remember(value: Pending | null) {
    setPending(value);
    try { if (value) sessionStorage.setItem(storageKey, JSON.stringify(value)); else sessionStorage.removeItem(storageKey); }
    catch { /* 无浏览器存储时仍保留本次页面内的恢复请求。 */ }
  }
  async function run(stage: string, work: () => Promise<void>) {
    if (guard.current || !canManage) return;
    guard.current = true; setBusy(stage); setMessage("");
    try { await work(); }
    catch (error) { setMessage(error instanceof Error ? error.message : "操作未完成，请重试。"); }
    finally { guard.current = false; setBusy(""); }
  }
  async function check(paths: string[]) {
    await run("正在检查具体源码候选", async () => {
      const result = await command("source-trust/check", { import_id: importId, target, paths: [...new Set([...(checked?.items.map(item => item.path) || []), ...paths])] }) as Checked;
      setSelected(previous => previous.filter(path => result.items.some(item => item.path === path && item.valid && checked?.items.some(old => old.path === path && old.evidence === item.evidence))));
      setChecked(result); setInput("");
    });
  }
  async function regenerate() {
    setPlanFailed(false);
    try { await onSaved(); }
    catch (error) { setPlanFailed(true); setMessage(`源码例外已保存，但重新检查或生成计划失败：${error instanceof Error ? error.message : "请重试"}`); }
  }
  async function persist(request: Pending) {
    remember(request);
    const result = await command(request.action, request.body);
    if (!result.saved) throw new Error("尚未核实配置保存结果，请使用核实并重试。");
    remember(null); setChecked(null); setSelected([]); setRevoke(null);
    setSavedMessage(request.action === "source-trust/revoke" ? "精确文件例外已撤销。" : "选中的源码例外已保存。最终导入仍需单独确认。");
    await grants.refetch();
    await regenerate();
  }
  return <section className="panel import-panel" aria-label="源码信任例外">
    <h2>源码信任例外</h2>
    <p>当前目录：{target}</p>
    <p>仅豁免当前仓库具体源码文件的敏感路径命名。输入、检查和勾选都不会保存授权。</p>
    <label className="field">具体源码相对路径<input value={input} disabled={disabled || Boolean(pending)} onChange={event => setInput(event.target.value)} /></label>
    <button type="button" disabled={disabled || !input || Boolean(pending)} onClick={() => void check([input])}>检查并添加到列表</button>
    <button type="button" disabled={disabled || !rejectedPaths.length || Boolean(pending)} onClick={() => void check(rejectedPaths)}>检查拒绝项并添加候选</button>
    {checked && <table><thead><tr><th>选择</th><th>仓库相对路径</th><th>检查结果</th></tr></thead><tbody>{checked.items.map(item => <tr key={item.path}>
      <td><input type="checkbox" aria-label={`授权 ${item.path}`} disabled={disabled || !item.valid || Boolean(pending)} checked={selected.includes(item.path)} onChange={event => setSelected(old => event.target.checked ? [...old, item.path] : old.filter(path => path !== item.path))} /></td><td>{item.path}</td><td>{item.message}</td>
    </tr>)}</tbody></table>}
    <button type="button" disabled={disabled || !selected.length || !checked || Boolean(pending)} onClick={() => void run("正在保存选中的源码例外", () => persist({ action: "source-trust/save", body: { import_id: importId, check_id: checked!.id, expected_digest: checked!.digest, paths: selected } }))}>将选中文件加入白名单</button>
    {pending && <div role="status"><p>上次写入结果尚未核实。请核实并重试原请求；不会扩大原选择。</p><button type="button" disabled={disabled} onClick={() => void run("正在核实上次写入", () => persist(pending))}>核实并重试原请求</button><button type="button" disabled={disabled} onClick={() => { remember(null); setChecked(null); setSelected([]); setMessage("已结束本次核实。已有配置不会回滚，请查看授权列表并重新检查候选。"); void grants.refetch(); }}>结束核实并重新检查候选</button></div>}
    <h3>当前仓库已保存授权</h3>
    {grants.error && <p role="alert">授权列表读取失败：{grants.error.message}</p>}
    {items.map(item => <div key={item.path}><code>{item.path}</code>{item.covering_rules.length ? <p>由目录规则覆盖：{item.covering_rules.join("、")}。请另行调整对应规则。</p> : <span> · 精确文件授权</span>}
      {item.revocable && <button type="button" disabled={disabled || Boolean(pending)} onClick={() => setRevoke(item.path)}>撤销 {item.path}</button>}
    </div>)}
    {legacy.map(path => <p key={path}>由目录规则覆盖：{path}。旧规则需另行调整，本页面不会改写。</p>)}
    {!items.length && !legacy.length && !grants.error && !grants.isPending && <p>当前仓库没有已保存的源码信任例外。</p>}
    {revoke && <div role="group" aria-label="确认撤销"><p>确认撤销精确文件例外：{revoke}？相关旧计划将失效。</p>
      <button type="button" disabled={disabled || Boolean(pending)} onClick={() => void run("正在撤销精确文件例外", async () => {
        const result = await command("source-trust/revoke-check", { import_id: importId, target, paths: [revoke] }) as Checked;
        await persist({ action: "source-trust/revoke", body: { import_id: importId, check_id: result.id, expected_digest: result.digest, paths: [revoke] } });
      })}>确认撤销</button>
      <button type="button" disabled={Boolean(busy)} onClick={() => setRevoke(null)}>取消撤销</button>
    </div>}
    {savedMessage && <p role="status">{savedMessage}</p>}
    {planFailed && <button type="button" disabled={disabled} onClick={() => void run("正在重新检查并生成计划", regenerate)}>重新检查并生成计划</button>}
    <ImportFeedback busy={Boolean(busy)} stage={busy} message={message} />
  </section>;
}
