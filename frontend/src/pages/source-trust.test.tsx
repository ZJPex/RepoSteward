import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { SourceTrustPanel } from "./source-trust";
const mocks = vi.hoisted(() => ({ command: vi.fn(), refetch: vi.fn(), grants: {} as Record<string, unknown> }));
vi.mock("../api/client", () => ({ command: mocks.command, useRead: () => ({ data: mocks.grants, error: null, isPending: false, refetch: mocks.refetch }) }));
const a = "src/credentials/a.py", b = "src/credentials/b.py";
const checked = { id: "check", digest: "digest", items: [{ path: a, valid: true, evidence: "a", message: "可申请" }, { path: b, valid: false, evidence: "", message: "禁止放行" }] };
const saved = vi.fn();
function show() { return render(<SourceTrustPanel importId="import" target="/repo" rejectedPaths={[a,b]} canManage onSaved={saved} />); }
beforeEach(() => { sessionStorage.clear(); mocks.command.mockReset(); mocks.refetch.mockReset(); saved.mockReset().mockResolvedValue(undefined); mocks.grants = { items: [], legacy_rules: [] }; });
afterEach(cleanup);
describe("源码信任例外", () => {
  it("检查不会保存，新候选默认未选、非法禁选，仅提交勾选集合", async () => {
    mocks.command.mockResolvedValueOnce(checked).mockResolvedValueOnce({ saved: true });
    show(); fireEvent.click(screen.getByText("检查拒绝项并添加候选"));
    const box = await screen.findByLabelText(`授权 ${a}`) as HTMLInputElement;
    expect(box.checked).toBe(false); expect(screen.getByLabelText(`授权 ${b}`).hasAttribute("disabled")).toBe(true);
    expect(mocks.command).toHaveBeenCalledTimes(1);
    fireEvent.click(box); fireEvent.click(screen.getByText("将选中文件加入白名单"));
    await waitFor(() => expect(mocks.command).toHaveBeenLastCalledWith("source-trust/save", { import_id: "import", check_id: "check", expected_digest: "digest", paths: [a] }));
    await waitFor(() => expect(saved).toHaveBeenCalledTimes(1));
    expect(screen.getByText(/最终导入仍需单独确认/)).toBeTruthy();
  });
  it("写入失败保留选择和原请求，刷新后仍可核实重放", async () => {
    mocks.command.mockResolvedValueOnce(checked).mockRejectedValueOnce(new Error("响应丢失"));
    const view = show(); fireEvent.click(screen.getByText("检查拒绝项并添加候选"));
    fireEvent.click(await screen.findByLabelText(`授权 ${a}`)); fireEvent.click(screen.getByText("将选中文件加入白名单"));
    await screen.findByText(/响应丢失/); expect((screen.getByLabelText(`授权 ${a}`) as HTMLInputElement).checked).toBe(true);
    view.unmount(); mocks.command.mockResolvedValueOnce({ saved: true }); show();
    fireEvent.click(screen.getByText("核实并重试原请求"));
    await waitFor(() => expect(mocks.command).toHaveBeenLastCalledWith("source-trust/save", { import_id: "import", check_id: "check", expected_digest: "digest", paths: [a] }));
    await waitFor(() => expect(saved).toHaveBeenCalledTimes(1));
  });
  it("保存成功与计划失败分别显示，再试仅重新检查", async () => {
    mocks.command.mockResolvedValueOnce(checked).mockResolvedValueOnce({ saved: true }); saved.mockRejectedValueOnce(new Error("仍有拒绝项"));
    show(); fireEvent.click(screen.getByText("检查拒绝项并添加候选")); fireEvent.click(await screen.findByLabelText(`授权 ${a}`)); fireEvent.click(screen.getByText("将选中文件加入白名单"));
    await screen.findByText(/但重新检查或生成计划失败/); expect(screen.getByText(/选中的源码例外已保存/)).toBeTruthy();
    fireEvent.click(screen.getByText("重新检查并生成计划")); await waitFor(() => expect(saved).toHaveBeenCalledTimes(2)); expect(mocks.command).toHaveBeenCalledTimes(2);
  });
  it("撤销必须确认，取消不写；目录覆盖不提供虚假撤销", async () => {
    mocks.grants = { items: [{ path: a, covering_rules: [], revocable: true }, { path: b, covering_rules: ["src/credentials"], revocable: false }], legacy_rules: ["src/credentials"] };
    mocks.command.mockResolvedValueOnce(checked).mockResolvedValueOnce({ saved: true }); show();
    expect(screen.queryByText(`撤销 ${b}`)).toBeNull(); expect(screen.getAllByText(/由目录规则覆盖/).length).toBeGreaterThan(0);
    fireEvent.click(screen.getByText(`撤销 ${a}`)); expect(mocks.command).not.toHaveBeenCalled(); fireEvent.click(screen.getByText("取消撤销")); expect(mocks.command).not.toHaveBeenCalled();
    fireEvent.click(screen.getByText(`撤销 ${a}`)); fireEvent.click(screen.getByText("确认撤销"));
    await waitFor(() => expect(mocks.command).toHaveBeenLastCalledWith("source-trust/revoke", { import_id: "import", check_id: "check", expected_digest: "digest", paths: [a] }));
  });
  it("手工路径修改不会把旧证据赋予新输入", async () => {
    mocks.command.mockResolvedValueOnce(checked); show();
    fireEvent.change(screen.getByLabelText("具体源码相对路径"), { target: { value: a } }); fireEvent.click(screen.getByText("检查并添加到列表"));
    fireEvent.click(await screen.findByLabelText(`授权 ${a}`)); fireEvent.change(screen.getByLabelText("具体源码相对路径"), { target: { value: "src/credentials/new.py" } });
    mocks.command.mockResolvedValueOnce({ saved: true }); fireEvent.click(screen.getByText("将选中文件加入白名单"));
    await waitFor(() => expect(mocks.command).toHaveBeenLastCalledWith("source-trust/save", { import_id: "import", check_id: "check", expected_digest: "digest", paths: [a] }));
  });
});
