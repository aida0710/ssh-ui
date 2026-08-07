import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { GroupsPanel, treeOrder } from "./GroupsPanel";
import { configApi } from "../api/config";

vi.mock("../api/config", async () => {
  const actual = await vi.importActual<typeof import("../api/config")>("../api/config");
  return {
    ...actual,
    configApi: {
      overview: vi.fn(),
      preview: vi.fn(),
      save: vi.fn(),
      renameGroup: vi.fn(),
      deleteGroup: vi.fn(),
    },
  };
});

// build01 は connections/company 内にあるため、"company" グループに
// 属する。射影がそれをエントリ上で報告し、ここではメタデータ
// フィールドを何も読まない。読むべきものがもう存在しないからである。
const overview = {
  entry: { path: "config", absolute: "/home/tester/.ssh/config" },
  files: [],
  hosts: [
    {
      identity: { path: "connections/company/build.conf", alias: "build01" },
      file: { path: "connections/company/build.conf", absolute: "/home/tester/.ssh/connections/company/build.conf" },
      line: 1,
      patterns: ["build01"],
      editable: true,
      group: "company",
    },
  ],
  metadata: {
    schemaVersion: 2,
    groups: [{ name: "company", settings: [{ keyword: "ServerAliveInterval", values: ["30"] }] }],
    hosts: [{ identity: { path: "connections/company/build.conf", alias: "build01" } }],
  },
  groups: [],
  diagnostics: [],
  notices: [],
};

beforeEach(() => {
  // モックされたクライアントはモジュールレベルであるため、そうしなければ記録された呼び出しが
  // テストをまたいで蓄積し、「呼ばれなかった」が誤ったテストについての主張になってしまう。
  vi.clearAllMocks();
  vi.mocked(configApi.overview).mockResolvedValue(overview as never);
  vi.mocked(configApi.preview).mockResolvedValue({
    operation: "config.groups",
    diffs: [{ path: "groups.sshc.conf", created: true, lines: [{ op: "insert", text: "Host build01", newLine: 1 }] }],
    effective: [{ alias: "build01", changes: [{ keyword: "Port", before: [], after: ["2222"] }] }],
  } as never);
});

// 名前変更、削除、ネストはファイルを書き換える操作であり、すべての
// グループに対して一度にではなく、選択したグループに対して提示される。
// 選択とは行をクリックすることであり、パネルがユーザーに求めることもそれである。
async function select(user: ReturnType<typeof userEvent.setup>, name: string) {
  await user.click(
    await screen.findByRole("heading", {
      // string の名前は testing-library では文字列全体の一致である——
      // Playwright では部分一致だが、これは異なる——ため、"company"は
      // "company/eu"も一緒に見つけることはない。
      name,
    }),
  );
}

describe("GroupsPanel", () => {
  it("lists groups with their directories, members and settings", async () => {
    render(<GroupsPanel />);

    expect(await screen.findByRole("heading", { name: "company" })).toBeInTheDocument();
    expect(screen.getByText("ServerAliveInterval 30")).toBeInTheDocument();
    expect(screen.getByText("build01")).toBeInTheDocument();
    // ディレクトリがグループであるため、パネルはユーザーに推測させるのではなく、
    // それがどこにあるかを述べる。
    expect(screen.getByText("connections/company/ · keys/company/")).toBeInTheDocument();
  });

  it("adds a nested group by naming its path and saves it", async () => {
    const user = userEvent.setup();
    render(<GroupsPanel />);

    // スラッシュがネスト構文のすべてである。名前が階層を運ぶため、
    // それと食い違い得る親フィールドは存在しない。
    await user.type(await screen.findByLabelText("New group name"), "company/work");
    await user.click(screen.getByRole("button", { name: "Add group" }));
    await user.click(screen.getByRole("button", { name: "Preview group changes" }));

    await waitFor(() => expect(configApi.preview).toHaveBeenCalledWith(expect.objectContaining({ kind: "groups" })));
    expect(await screen.findByText(/Port: unset → 2222/)).toBeInTheDocument();

    vi.mocked(configApi.save).mockResolvedValue({
      transactionId: "t1",
      written: ["groups.sshc.conf"],
      preview: { operation: "config.groups", diffs: [] },
    } as never);
    await user.click(screen.getByRole("button", { name: "Save groups" }));

    await waitFor(() =>
      expect(configApi.save).toHaveBeenCalledWith(
        expect.objectContaining({
          kind: "groups",
          metadata: expect.objectContaining({
            groups: expect.arrayContaining([expect.objectContaining({ name: "company/work" })]),
          }),
        }),
      ),
    );
  });

  it("refuses a name that is not a safe relative directory", async () => {
    const user = userEvent.setup();
    render(<GroupsPanel />);

    await user.type(await screen.findByLabelText("New group name"), "../escape");
    await user.click(screen.getByRole("button", { name: "Add group" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("relative directory path");
    expect(configApi.save).not.toHaveBeenCalled();
  });

  it("renames a group through the server rather than editing the document", async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.renameGroup).mockResolvedValue({
      transactionId: "t1",
      written: ["config"],
      preview: { operation: "config.group_rename", diffs: [] },
    } as never);
    render(<GroupsPanel />);

    await select(user, "company");
    await user.type(screen.getByLabelText("Rename company to"), "corp");
    await user.click(screen.getByRole("button", { name: "Rename company" }));

    // グループはディレクトリであるため、名前変更は N 個のファイル移動に加え
    // Include 領域、さらにその鍵を名指すすべての IdentityFile に及ぶ。
    // クライアントには組み立てられない一つのトランザクションであり、サーバーにそれを求める。
    await waitFor(() => expect(configApi.renameGroup).toHaveBeenCalledWith("company", "corp"));
    expect(configApi.save).not.toHaveBeenCalled();
  });

  it("refuses a rename onto a group that already exists instead of merging", async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.overview).mockResolvedValue({
      ...overview,
      metadata: { ...overview.metadata, groups: [{ name: "company" }, { name: "lab" }] },
    } as never);
    render(<GroupsPanel />);

    await select(user, "company");
    await user.type(screen.getByLabelText("Rename company to"), "lab");
    await user.click(screen.getByRole("button", { name: "Rename company" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("lab already exists");
    // サーバーには何も求められていないため、マージは偶然には起こらない。
    expect(configApi.renameGroup).not.toHaveBeenCalled();
    expect(screen.getByRole("heading", { name: "company" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "lab" })).toBeInTheDocument();
  });

  it("refuses an empty rename", async () => {
    const user = userEvent.setup();
    render(<GroupsPanel />);

    await select(user, "company");
    await user.click(screen.getByRole("button", { name: "Rename company" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("needs a name of its own");
  });

  it("removes a group by naming where its connections go", async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.overview).mockResolvedValue({
      ...overview,
      metadata: { ...overview.metadata, groups: [{ name: "company" }, { name: "archive" }] },
    } as never);
    vi.mocked(configApi.deleteGroup).mockResolvedValue({
      transactionId: "t1",
      written: ["config"],
      preview: { operation: "config.group_delete", diffs: [] },
    } as never);
    render(<GroupsPanel />);

    await select(user, "company");

    // グループの削除はその接続を再配置するだけで、何も削除
    // しない。宛先は、削除が何をするかを述べる一文の後、削除の
    // 中で尋ねる。削除に一度も触れないラベルを持つプルダウンが単独で
    // 置かれているのではない。
    await user.click(await screen.findByRole("button", { name: "Remove company" }));
    expect(screen.getByText(/takes away its Include line/)).toBeInTheDocument();
    expect(screen.getByText(/No configuration file is deleted/)).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Move its connections to"), "archive");
    await user.click(screen.getByRole("button", { name: "Remove company" }));

    await waitFor(() => expect(configApi.deleteGroup).toHaveBeenCalledWith("company", "archive"));
  });
  it("marks a group that is only in the draft, and will not write files for it", async () => {
    // パネルには二種類のコントロールがあり、以前は違いを何も示していなかった。
    // ここで追加されたグループは Save するまで画面上にしか存在しないが、
    // ディレクトリを持つグループとまったく同じに見え、Rename と Remove を
    // 提示していた——ファイルを書き込む操作を、ファイルを持たないグループに対して。
    const user = userEvent.setup();
    render(<GroupsPanel />);

    await user.type(await screen.findByLabelText(/New group name/i), "lab");
    await user.click(screen.getByRole("button", { name: "Add group" }));

    expect(await screen.findByText("Not saved")).toBeInTheDocument();
    await select(user, "lab");
    expect(screen.getByRole("button", { name: "Remove lab" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Rename lab" })).toBeDisabled();
    expect(screen.getByText(/no directory yet/)).toBeInTheDocument();
    // そしてページは、どちらの半分がそもそも Save を必要とするかを述べる。
    expect(screen.getByText(/until you press Save/)).toBeInTheDocument();
  });

  // バグ。パネルは Include 順を決める規則——最も深いグループを先に——で
  // 並べ、それをツリーであるかのようにインデントしていた。すべての
  // 子が親の上に浮かび、親が最後に来るため、ネストがまるで
  // 機能していないかのように読めていた。
  it("lists a parent before its children", async () => {
    vi.mocked(configApi.overview).mockResolvedValue({
      ...overview,
      metadata: {
        ...overview.metadata,
        groups: [{ name: "office/tokyo" }, { name: "hpc" }, { name: "office" }, { name: "office/osaka" }],
      },
    } as never);
    render(<GroupsPanel />);

    await screen.findByRole("heading", { name: "hpc" });
    const list = screen.getByRole("list", { name: "Groups, parent before child" });
    const headings = within(list)
      .getAllByRole("heading", { level: 3 })
      .map((heading) => heading.textContent);
    expect(headings).toEqual(["hpc", "office", "office/osaka", "office/tokyo"]);
  });

  it("orders siblings by display order and keeps them under their own parent", () => {
    const ordered = treeOrder([
      { name: "office/tokyo" },
      { name: "office", order: 2 },
      { name: "hpc", order: 1 },
      { name: "office/osaka", order: -1 },
    ]).map((group) => group.name);

    // hpc は office より、osaka は tokyo より、それぞれ自分自身の order で先に来る。
    // そしてどちらの子もファイルの order がするように先頭へ逃げ出すことはない。
    expect(ordered).toEqual(["hpc", "office", "office/osaka", "office/tokyo"]);
  });

  it("offers a child group from the group it would sit inside", async () => {
    const user = userEvent.setup();
    render(<GroupsPanel />);

    await select(user, "company");
    await user.click(screen.getByRole("button", { name: "Add a group inside company" }));

    // パスは事前に入力されているため、ユーザーは子の名前だけを
    // 入力すればよい——以前ネストはページ下部のスラッシュについての一文
    // からしか発見できなかった。
    expect(screen.getByLabelText("New group name")).toHaveValue("company/");
  });
});

describe("hiding a group from the connections tree", () => {
  // "company"は build01 を直接保持する。"company/eu"は何も保持
  // しない。これが他のグループを含むために作られたグループの姿である。

  // Hiding は metadata.json にのみ存在する三つの設定の一つで
  // あるため、colour や display order と共にインスペクターへ移った。
  // 以前ここで検証されていたものは GroupInspector.test.tsx にある。

  // connections/下にあり、どの Include も名指さないディレクトリはグループのように
  // 見えるが、何にも読まれない。エンジンは常に知っていたが、何もそれを示していなかった。
  it("shows a directory that looks like a group but is declared by nothing", async () => {
    vi.mocked(configApi.overview).mockResolvedValue({
      ...overview,
      notices: [
        { code: "group_not_declared", detail: "scratch", path: "connections/scratch" },
        { code: "group_empty", detail: "archive", path: "connections/archive" },
      ],
    } as never);
    render(<GroupsPanel />);

    expect(await screen.findByText(/no Include line names it/)).toBeInTheDocument();

    // 空のグループはそのうちの一つではない。それは作られた直後の
    // すべてのグループが置かれる状態であり、下の行は既に"Members: none"
    // と読める——それをアンバーで再度報告することは、何かが起きたことを
    // 意味するはずの colour を、何も起きていないことに費やしてしまう。
    expect(screen.queryByText(/declared and holds nothing/)).toBeNull();
  });
});
