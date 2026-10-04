import { useEffect, useRef, useState } from "react";

export type ImportDiagnostics = {
  complete: boolean;
  reason: string;
  checked_files: number;
  items: {
    path: string;
    reason: string;
    message: string;
    can_request_exception: boolean;
    coverage: { path: string; kind: string }[];
  }[];
};

export function ImportFeedback({ busy, stage, message, diagnostics }: {
  busy: boolean;
  stage: string;
  message?: string;
  diagnostics?: ImportDiagnostics;
}) {
  const [seconds, setSeconds] = useState(0);
  const result = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!busy) return;
    const start = Date.now();
    const timer = setInterval(() => setSeconds(Math.floor((Date.now() - start) / 1000)), 1000);
    return () => { clearInterval(timer); setSeconds(0); };
  }, [busy]);
  useEffect(() => {
    if (!busy && (message || diagnostics)) {
      result.current?.focus();
      result.current?.scrollIntoView?.({ block: "nearest" });
    }
  }, [busy, message, diagnostics]);
  return <div ref={result} tabIndex={-1} aria-live="polite">
    {busy && <p role="status">{stage} · 已等待 {seconds} 秒</p>}
    {!busy && message && <p role="alert">{message}</p>}
    {!busy && diagnostics && <>
      <p>{diagnostics.complete ? "检查已完成，以下文件阻止导入。" : "检查不完整：仍有未确认部分，不能视为全部通过。"} 已检查 {diagnostics.checked_files} 个文件。</p>
      <table aria-label="导入拒绝项"><thead><tr><th>相对路径</th><th>拒绝原因</th><th>源码信任例外</th><th>已有规则覆盖</th></tr></thead>
        <tbody>{diagnostics.items.map(item => <tr key={item.path}>
          <td>{item.path}</td><td>{item.message}</td><td>{item.can_request_exception ? "可申请" : "禁止放行"}</td>
          <td>{item.coverage.length ? item.coverage.map(rule => `${rule.kind === "directory" ? "由目录规则覆盖" : "精确文件规则"}：${rule.path}`).join("；") : "无"}</td>
        </tr>)}</tbody>
      </table>
    </>}
  </div>;
}
