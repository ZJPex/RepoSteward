import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { ImportPage } from "./imports";
import { ImportFeedback } from "./import-feedback";

const mocks = vi.hoisted(() => ({ command: vi.fn(), fixtures: {} as Record<string, unknown> }));
vi.mock("../api/client", () => ({
  command: mocks.command,
  useRead: (name: string) => ({ data: mocks.fixtures[name], isPending: false, isFetching: false, error: null, refetch: vi.fn() }),
}));
const diagnostics = { complete: false, reason: "scan_limit", checked_files: 1, items: [{ path: "src/credentials/main.py", reason: "sensitive_path", message: "敏感名称", can_request_exception: true, coverage: [] }] };
function show(path = "/imports") {
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter initialEntries={[path]}><Routes><Route path="/imports/:importId?" element={<ImportPage />} /></Routes></MemoryRouter></QueryClientProvider>);
}
beforeEach(() => {
  mocks.command.mockReset();
  mocks.fixtures = { session: { capabilities: ["manage_local"] } };
});
afterEach(() => { cleanup(); vi.useRealTimers(); });

describe("导入检查反馈", () => {
  it("显示真实等待时间并在完成时定位结构化结果", () => {
    vi.useFakeTimers();
    const { rerender } = render(<ImportFeedback busy stage="正在检查" />);
    act(() => { vi.advanceTimersByTime(2100); });
    expect(screen.getByRole("status").textContent).toContain("已等待 2 秒");
    rerender(<ImportFeedback busy={false} stage="正在检查" message="检查失败" diagnostics={diagnostics} />);
    expect(screen.queryByRole("status")).toBeNull();
    expect(screen.getByText(/检查不完整/)).toBeTruthy();
    expect(screen.getByRole("table", { name: "导入拒绝项" }).parentElement).toBe(document.activeElement);
  });
  it("直接识别处理中阻止重复提交，失败保留输入且错误紧邻按钮", async () => {
    let reject!: (error: Error) => void;
    mocks.command.mockReturnValue(new Promise((_, fail) => { reject = fail; }));
    show();
    fireEvent.change(screen.getByLabelText("项目来源"), { target: { value: "local_path" } });
    const input = screen.getByLabelText("本地绝对路径") as HTMLInputElement;
    fireEvent.change(input, { target: { value: "/tmp/project" } });
    const button = screen.getByText("识别项目");
    fireEvent.click(button); fireEvent.click(button);
    await waitFor(() => expect(button.hasAttribute("disabled")).toBe(true));
    expect(mocks.command).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("status").textContent).toContain("正在提交识别请求");
    await act(async () => { reject(new Error("路径检查失败")); });
    expect(input.value).toBe("/tmp/project");
    await waitFor(() => expect(button.parentElement?.contains(screen.getByRole("alert"))).toBe(true));
  });
  it("GitHub 关联目录的计划等待、拒绝表格和失败输入一致", async () => {
    mocks.fixtures.import = { id: "id", source: { value: "https://github.com/owner/repo" }, inspection_id: "inspection", inspection: { remote: { repository: "owner/repo" } }, operations: [] };
    let reject!: (error: Error) => void;
    mocks.command.mockReturnValue(new Promise((_, fail) => { reject = fail; }));
    show("/imports/id");
    const input = screen.getByLabelText("已有 Git 目录") as HTMLInputElement;
    fireEvent.change(input, { target: { value: "/tmp/project" } });
    const button = screen.getByText("生成导入计划");
    fireEvent.click(button); fireEvent.click(button);
    await waitFor(() => expect(button.hasAttribute("disabled")).toBe(true));
    expect(mocks.command).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("status").textContent).toContain("正在检查工作区并生成计划");
    await act(async () => { reject(Object.assign(new Error("导入被拒绝"), { diagnostics })); });
    expect(input.value).toBe("/tmp/project");
    await waitFor(() => expect(screen.getByText("src/credentials/main.py")).toBeTruthy());
    expect(button.parentElement?.contains(screen.getByRole("table"))).toBe(true);
  });
});
