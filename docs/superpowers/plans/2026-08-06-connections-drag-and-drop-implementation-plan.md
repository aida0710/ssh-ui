# Connections drag and drop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a connection be dragged into a group and a group be dragged inside another, in the Connections tree, without adding a server route or a dependency.

**Architecture:** `ConnectionTree` gains drag sources on connection rows and group headings, and drop targets on group headings. What is being dragged is held in component state, because a `dragover` handler may read `dataTransfer.types` but not its data. The tree calls back with a typed payload; `ConnectionsPage` turns each payload into a request that already exists. Empty declared groups are rendered so a group cannot become undroppable by being emptied.

**Tech Stack:** React 19.2.8, TypeScript 5.9.3, Vitest 4.1.1, Testing Library, native HTML5 drag events. No new dependency.

## Global Constraints

- No new npm or Go dependency. `package.json`, `package-lock.json`, `go.mod` and `go.sum` must be unchanged at the end.
- No Go code changes. `api/openapi.yaml` unchanged, so `make verify-generated` stays clean.
- Every user-visible string goes through `useTranslate` and is added to **both** locales in `web/src/i18n/messages.ts` (English block and Japanese block).
- `internal/ui/dist` is a committed build artefact. Run `make build` before the final commit so the embedded bundle matches `web/src`.
- Drag is never the only way to reach an operation. Every drop must have a keyboard equivalent.
- The server is the guard. Refused drop targets are convenience; a refusal that reaches the server is still shown through the page's existing `setProblem`.

---

### Task 1: The host detail's group button accepts "no group"

The button is disabled when the select reads "no group", so there is no keyboard
way to take a connection out of a group. That gap exists today; the drag would
otherwise become the only way to do it.

**Files:**
- Modify: `web/src/connections/HostDetail.tsx:357` (the `disabled` expression) and its `onMoveToGroup` prop type
- Modify: `web/src/connections/ConnectionsPage.tsx:149-158` (`onMoveToGroup`)
- Test: `web/src/connections/HostDetail.test.tsx`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `onMoveToGroup(group: string)` where `""` means "out of every group,
  back into the entry file". Task 4 calls the same handler.

- [ ] **Step 1: Write the failing test**

Append to `web/src/connections/HostDetail.test.tsx`:

```tsx
describe("taking a connection out of every group", () => {
  it("offers the empty choice for a host that is in a group", async () => {
    const onMoveToGroup = vi.fn();
    renderDetail({ group: "home", onMoveToGroup });

    await userEvent.selectOptions(screen.getByLabelText("Primary group"), "");
    const button = screen.getByRole("button", { name: "Move to group" });
    expect(button).toBeEnabled();

    await userEvent.click(button);
    expect(onMoveToGroup).toHaveBeenCalledWith("");
  });

  it("offers nothing to do for a host that is in no group already", async () => {
    renderDetail({ group: "", onMoveToGroup: vi.fn() });

    await userEvent.selectOptions(screen.getByLabelText("Primary group"), "");
    expect(screen.getByRole("button", { name: "Move to group" })).toBeDisabled();
  });
});
```

Add the `renderDetail` helper near the top of the file if one does not already
exist, matching the props the existing tests pass:

```tsx
function renderDetail(options: { group: string; onMoveToGroup: (group: string) => void }) {
  const detail = buildDetail();
  detail.form.entry.group = options.group;
  render(
    <HostDetailPanel
      detail={detail}
      groups={[{ name: "home" }, { name: "work" }]}
      onFieldEdits={vi.fn()}
      onRawBlock={vi.fn()}
      onRename={vi.fn()}
      onComment={vi.fn()}
      onMetadata={vi.fn()}
      onMoveToGroup={options.onMoveToGroup}
      onDelete={vi.fn()}
      onOpenFile={vi.fn()}
    />,
  );
}
```

Read the existing tests in the file first and copy their prop list exactly; the
list above is the shape as of this plan and the file is the authority.

- [ ] **Step 2: Run the test and watch it fail**

```
cd web && npx vitest run src/connections/HostDetail.test.tsx
```

Expected: the first test fails because the button is disabled.

- [ ] **Step 3: Make the button accept the empty choice**

In `web/src/connections/HostDetail.tsx`, replace the `disabled` expression:

```tsx
disabled={moveTo === (detail.form.entry.group ?? "")}
```

The button is now disabled only when the choice is the group the host is already
in — which covers the empty choice for a host that is already ungrouped.

Change the hint under the label so the empty choice is explained. In
`web/src/i18n/messages.ts`, add to the English block beside the other `host.`
keys:

```ts
  "host.groupNoneMeans": "Choosing no group moves the connection back into ~/.ssh/config, at the end of the file.",
```

and to the Japanese block:

```ts
  "host.groupNoneMeans": "「なし」を選ぶと接続は ~/.ssh/config の末尾へ戻ります。",
```

Render it under the existing `host.groupIsADirectory` hint:

```tsx
<p className={hintText}>{t("host.groupNoneMeans")}</p>
```

- [ ] **Step 4: Send the ungrouping request**

In `web/src/connections/ConnectionsPage.tsx`, replace `onMoveToGroup`:

```tsx
  // An empty group means "out of every group", which is a move to the entry
  // file rather than into a directory. The entry file's bytes are read first so
  // the destination is held to its own precondition, exactly as a file-to-file
  // move is.
  async function onMoveToGroup(group: string) {
    if (detail === null || selection === null) return;
    const source = selection;
    const path = detail.form.entry.file.path ?? "";
    if (group !== "") {
      void submit({
        kind: "move",
        path,
        base: detail.file.contents,
        alias: source.alias,
        destinationGroup: group,
      });
      return;
    }
    try {
      const destination = await configApi.file("config");
      await submit({
        kind: "move",
        path,
        base: detail.file.contents,
        alias: source.alias,
        destinationPath: "config",
        destinationBase: destination.contents,
      }, false);
      setSelection({ path: "config", alias: source.alias });
      setDetail(await configApi.host("config", source.alias));
    } catch (error) {
      setProblem(toProblem(error));
    }
  }
```

- [ ] **Step 5: Cover the request shape**

Append to `web/src/connections/ConnectionsPage.test.tsx`, following the file's
existing pattern for asserting on `configApi.save` calls:

```tsx
it("moves a connection out of every group by sending it to the entry file", async () => {
  const api = buildConfigApi({
    host: vi.fn().mockResolvedValue(detailInGroup("home")),
    file: vi.fn().mockResolvedValue({
      file: { path: "config", absolute: "/home/tester/.ssh/config" },
      contents: "Host bastion\n", digest: "d", editable: true, exists: true,
    }),
  });
  renderPage(api);

  await userEvent.click(await screen.findByRole("button", { name: /nas/ }));
  await userEvent.selectOptions(await screen.findByLabelText("Primary group"), "");
  await userEvent.click(screen.getByRole("button", { name: "Move to group" }));

  await waitFor(() =>
    expect(api.save).toHaveBeenCalledWith(
      expect.objectContaining({
        kind: "move",
        alias: "nas",
        destinationPath: "config",
        destinationBase: "Host bastion\n",
      }),
    ),
  );
});
```

Read the file's existing helpers before writing this; reuse whatever it already
has for building an API double and rendering the page rather than inventing new
ones.

- [ ] **Step 6: Run the tests**

```
cd web && npx vitest run src/connections
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add web/src/connections/HostDetail.tsx web/src/connections/HostDetail.test.tsx \
        web/src/connections/ConnectionsPage.tsx web/src/connections/ConnectionsPage.test.tsx \
        web/src/i18n/messages.ts
git commit -m "Let a connection be taken out of every group without a mouse"
```

---

### Task 2: A declared group with nothing in it still has a heading

`ConnectionTree.tsx:135` renders nothing for a section with no items, so a group
disappears when its last connection leaves. Dragging the last connection out
would destroy the only thing you could drag it back onto.

**Files:**
- Modify: `web/src/connections/ConnectionTree.tsx:134-137`
- Modify: `web/src/i18n/messages.ts`
- Test: `web/src/connections/ConnectionTree.test.tsx`

**Interfaces:**
- Consumes: nothing.
- Produces: every declared group name has a `<h2>` on screen whenever the tree
  groups by group. Task 3's drop targets rely on this.

- [ ] **Step 1: Write the failing test**

Append to `web/src/connections/ConnectionTree.test.tsx`:

```tsx
it("shows a declared group that holds nothing", () => {
  const empty: Overview = {
    ...overview,
    metadata: { ...overview.metadata, groups: [{ name: "home" }, { name: "work" }] },
  };
  render(
    <ConnectionTree overview={empty} selected={null} onSelect={vi.fn()} onOpenPatternRule={vi.fn()} />,
  );

  // "work" holds nothing. Hiding it would mean a group created in the Groups
  // panel never appears here, and — once dragging exists — that emptying a
  // group removes the only place it could be refilled from.
  expect(screen.getByRole("heading", { name: "work" })).toBeInTheDocument();
  expect(screen.getByText("No connection is in this group.")).toBeInTheDocument();
});

it("still hides a file that holds nothing when grouping by file", async () => {
  render(
    <ConnectionTree overview={overview} selected={null} onSelect={vi.fn()} onOpenPatternRule={vi.fn()} />,
  );
  await userEvent.click(screen.getByRole("button", { name: "Files" }));

  // A file is not a place anything can be put, so an empty one is noise.
  expect(screen.queryByText("No connection is in this group.")).not.toBeInTheDocument();
});
```

- [ ] **Step 2: Run the test and watch it fail**

```
cd web && npx vitest run src/connections/ConnectionTree.test.tsx
```

Expected: the first test fails — no heading named "work".

- [ ] **Step 3: Add the message in both locales**

In `web/src/i18n/messages.ts`, English block beside the other `tree.` keys:

```ts
  "tree.groupEmpty": "No connection is in this group.",
```

Japanese block:

```ts
  "tree.groupEmpty": "このグループに接続はありません。",
```

- [ ] **Step 4: Render empty group sections**

In `web/src/connections/ConnectionTree.tsx`, replace the section map. The
sections built for the "files" mode keep their current behaviour; only groups
render when empty.

```tsx
      {sections.map((section) =>
        section.items.length === 0 && grouping === "files" ? null : (
          <section key={section.title} className="flex flex-col gap-1">
            <h2 className="text-xs font-semibold uppercase tracking-wide text-zinc-500">
              {section.title === ungrouped ? t("tree.ungrouped") : section.title}
            </h2>
            {section.items.length === 0 ? (
              <p className="px-2 py-1 text-xs text-zinc-500">{t("tree.groupEmpty")}</p>
            ) : (
              <ul>
                {/* the existing item map, unchanged */}
              </ul>
            )}
          </section>
        ),
      )}
```

Move the existing `<ul>` and its contents inside the new conditional without
editing them.

- [ ] **Step 5: Run the tests**

```
cd web && npx vitest run src/connections/ConnectionTree.test.tsx
```

Expected: PASS, including every test that was already there.

- [ ] **Step 6: Commit**

```bash
git add web/src/connections/ConnectionTree.tsx web/src/connections/ConnectionTree.test.tsx \
        web/src/i18n/messages.ts
git commit -m "Show a group that holds nothing, so it can be filled again"
```

---

### Task 3: Deciding which drops are possible

A pure module, tested on its own, so the rules are readable without a rendered
tree. The tree and the page both consume it.

**Files:**
- Create: `web/src/connections/dragdrop.ts`
- Test: `web/src/connections/dragdrop.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces:

```ts
export type DragPayload =
  | { kind: "connection"; path: string; alias: string; group: string }
  | { kind: "group"; name: string };

export const dragMimeType = "application/x-ssh-ui-drag";

export function canDrop(payload: DragPayload, target: string, groups: string[]): boolean;
```

`target` is a group name, or the empty string for the "no group" heading.
`groups` is every declared group name. Task 4 and Task 5 both call `canDrop`.

- [ ] **Step 1: Write the failing test**

Create `web/src/connections/dragdrop.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { canDrop, type DragPayload } from "./dragdrop";

const groups = ["home", "work", "work/eu", "client-a"];
const nas: DragPayload = { kind: "connection", path: "connections/home/nas.conf", alias: "nas", group: "home" };
const work: DragPayload = { kind: "group", name: "work" };

describe("canDrop, for a connection", () => {
  it("accepts another group", () => {
    expect(canDrop(nas, "work", groups)).toBe(true);
  });

  it("accepts the no-group heading, which is a move back to the entry file", () => {
    expect(canDrop(nas, "", groups)).toBe(true);
  });

  it("refuses the group it is already in, because there is nothing to do", () => {
    expect(canDrop(nas, "home", groups)).toBe(false);
  });

  it("refuses the no-group heading when it is ungrouped already", () => {
    const loose: DragPayload = { kind: "connection", path: "config", alias: "bastion", group: "" };
    expect(canDrop(loose, "", groups)).toBe(false);
  });
});

describe("canDrop, for a group", () => {
  it("accepts another group as a new parent", () => {
    expect(canDrop(work, "client-a", groups)).toBe(true);
  });

  it("refuses itself", () => {
    expect(canDrop(work, "work", groups)).toBe(false);
  });

  // A group cannot contain itself. The server refuses this as
  // ErrGroupSelfNesting; the target is simply not offered.
  it("refuses its own descendant", () => {
    expect(canDrop(work, "work/eu", groups)).toBe(false);
  });

  it("refuses a parent that already holds a group of that name", () => {
    expect(canDrop({ kind: "group", name: "client-a/work" }, "", ["client-a/work", "work"])).toBe(false);
  });

  it("accepts the no-group heading for a nested group", () => {
    expect(canDrop({ kind: "group", name: "work/eu" }, "", groups)).toBe(true);
  });

  it("refuses the no-group heading for a group already at the top", () => {
    expect(canDrop(work, "", groups)).toBe(false);
  });

  // The key scanner walks eight directories down from ~/.ssh and "keys" takes
  // one, so a key in a seventh group segment would vanish from the inventory.
  // ValidateGroupName refuses more than six segments; this refuses the drop
  // that would produce one.
  it("refuses a nesting deeper than six segments", () => {
    const deep = ["a", "a/b/c/d/e/f"];
    expect(canDrop({ kind: "group", name: "a" }, "a/b/c/d/e/f", deep)).toBe(false);
  });
});
```

- [ ] **Step 2: Run the test and watch it fail**

```
cd web && npx vitest run src/connections/dragdrop.test.ts
```

Expected: FAIL — cannot resolve `./dragdrop`.

- [ ] **Step 3: Write the module**

Create `web/src/connections/dragdrop.ts`:

```ts
// What a drag is carrying, and which drops it makes sense to offer.
//
// The rules here mirror refusals the server already makes. They exist so a
// target that cannot work is not offered, not to enforce anything: every drop
// still goes through the API, and a refusal that arrives is still shown.

export type DragPayload =
  | { kind: "connection"; path: string; alias: string; group: string }
  | { kind: "group"; name: string };

// A private type on dataTransfer, so a drag that began outside this page is not
// mistaken for one of these. It is only ever read from `types`, because a
// dragover handler may not read the data itself.
export const dragMimeType = "application/x-ssh-ui-drag";

// MaxGroupSegments in internal/application/grouppath.go. The limit comes from
// the key scanner, not from anything here.
const maxGroupSegments = 6;

function segments(name: string): number {
  return name === "" ? 0 : name.split("/").length;
}

function basename(name: string): string {
  const index = name.lastIndexOf("/");
  return index < 0 ? name : name.slice(index + 1);
}

function isDescendant(name: string, candidate: string): boolean {
  return candidate === name || candidate.startsWith(`${name}/`);
}

export function canDrop(payload: DragPayload, target: string, groups: string[]): boolean {
  if (payload.kind === "connection") {
    return payload.group !== target;
  }
  if (isDescendant(payload.name, target)) return false;
  const moved = target === "" ? basename(payload.name) : `${target}/${basename(payload.name)}`;
  if (moved === payload.name) return false;
  if (groups.includes(moved)) return false;
  return segments(moved) <= maxGroupSegments;
}
```

- [ ] **Step 4: Run the test**

```
cd web && npx vitest run src/connections/dragdrop.test.ts
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add web/src/connections/dragdrop.ts web/src/connections/dragdrop.test.ts
git commit -m "Say which drops are worth offering"
```

---

### Task 4: The tree drags and drops

**Files:**
- Modify: `web/src/connections/ConnectionTree.tsx`
- Test: `web/src/connections/ConnectionTree.test.tsx`

**Interfaces:**
- Consumes: `canDrop`, `DragPayload`, `dragMimeType` from Task 3. The empty
  group headings from Task 2.
- Produces: a new required prop on `ConnectionTree`:

```ts
onDrop: (payload: DragPayload, target: string) => void;
```

`target` is a group name or `""` for the no-group heading. Task 5 supplies it.

- [ ] **Step 1: Write the failing test**

Append to `web/src/connections/ConnectionTree.test.tsx`:

```tsx
import { fireEvent } from "@testing-library/react";
import { dragMimeType, type DragPayload } from "./dragdrop";

// jsdom has no drag implementation, so the transfer is a stub carrying the two
// things the component uses: the private type and the payload.
function transfer(payload: DragPayload) {
  const store = new Map<string, string>([[dragMimeType, JSON.stringify(payload)]]);
  return {
    types: [...store.keys()],
    setData: (type: string, value: string) => void store.set(type, value),
    getData: (type: string) => store.get(type) ?? "",
    effectAllowed: "move",
    dropEffect: "move",
  };
}

function renderTree(onDrop = vi.fn()) {
  const withGroups: Overview = {
    ...overview,
    metadata: { ...overview.metadata, groups: [{ name: "home" }, { name: "work" }] },
  };
  render(
    <ConnectionTree
      overview={withGroups}
      selected={null}
      onSelect={vi.fn()}
      onOpenPatternRule={vi.fn()}
      onDrop={onDrop}
    />,
  );
  return onDrop;
}

describe("dragging in the tree", () => {
  it("moves a connection onto another group's heading", () => {
    const onDrop = renderTree();
    const row = screen.getByRole("button", { name: /nas/ });
    const target = screen.getByRole("heading", { name: "work" });

    fireEvent.dragStart(row, { dataTransfer: transfer({ kind: "connection", path: "connections/home/nas.conf", alias: "nas", group: "home" }) });
    fireEvent.drop(target, { dataTransfer: transfer({ kind: "connection", path: "connections/home/nas.conf", alias: "nas", group: "home" }) });

    expect(onDrop).toHaveBeenCalledWith(
      { kind: "connection", path: "connections/home/nas.conf", alias: "nas", group: "home" },
      "work",
    );
  });

  it("moves a connection onto the no-group heading", () => {
    const onDrop = renderTree();
    const row = screen.getByRole("button", { name: /nas/ });
    const payload: DragPayload = { kind: "connection", path: "connections/home/nas.conf", alias: "nas", group: "home" };

    fireEvent.dragStart(row, { dataTransfer: transfer(payload) });
    fireEvent.drop(screen.getByRole("heading", { name: "Ungrouped" }), { dataTransfer: transfer(payload) });

    expect(onDrop).toHaveBeenCalledWith(payload, "");
  });

  it("does not call back for a drop on the group the connection is already in", () => {
    const onDrop = renderTree();
    const payload: DragPayload = { kind: "connection", path: "connections/home/nas.conf", alias: "nas", group: "home" };

    fireEvent.dragStart(screen.getByRole("button", { name: /nas/ }), { dataTransfer: transfer(payload) });
    fireEvent.drop(screen.getByRole("heading", { name: "home" }), { dataTransfer: transfer(payload) });

    expect(onDrop).not.toHaveBeenCalled();
  });

  it("nests one group inside another", () => {
    const onDrop = renderTree();
    const payload: DragPayload = { kind: "group", name: "work" };

    fireEvent.dragStart(screen.getByRole("heading", { name: "work" }), { dataTransfer: transfer(payload) });
    fireEvent.drop(screen.getByRole("heading", { name: "home" }), { dataTransfer: transfer(payload) });

    expect(onDrop).toHaveBeenCalledWith(payload, "home");
  });

  it("drops nothing while grouping by file", async () => {
    const onDrop = renderTree();
    await userEvent.click(screen.getByRole("button", { name: "Files" }));
    const payload: DragPayload = { kind: "connection", path: "connections/home/nas.conf", alias: "nas", group: "home" };

    fireEvent.dragStart(screen.getByRole("button", { name: /nas/ }), { dataTransfer: transfer(payload) });
    fireEvent.drop(screen.getByRole("heading", { name: "config" }), { dataTransfer: transfer(payload) });

    expect(onDrop).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run the test and watch it fail**

```
cd web && npx vitest run src/connections/ConnectionTree.test.tsx
```

Expected: FAIL — `onDrop` is not a prop and no heading is a drop target.

- [ ] **Step 3: Add the drag state and the handlers**

In `web/src/connections/ConnectionTree.tsx`, add to the imports:

```tsx
import { canDrop, dragMimeType, type DragPayload } from "./dragdrop";
```

Add to `ConnectionTreeProps`:

```tsx
  // Where a dragged connection or group was dropped. The target is a group
  // name, or the empty string for the no-group heading.
  onDrop: (payload: DragPayload, target: string) => void;
```

Add to the component body, beside the other state:

```tsx
  // What is being dragged, held here because a dragover handler may read
  // dataTransfer.types but not its data — the data is protected until the drop.
  // So a target cannot inspect the drag to decide whether to accept it, and
  // deciding from state is how that is done.
  const [dragging, setDragging] = useState<DragPayload | null>(null);
  const groupNames = useMemo(
    () => (overview.metadata.groups ?? []).map((group) => group.name),
    [overview.metadata.groups],
  );

  function startDrag(event: React.DragEvent, payload: DragPayload) {
    event.dataTransfer.setData(dragMimeType, JSON.stringify(payload));
    event.dataTransfer.effectAllowed = "move";
    setDragging(payload);
  }

  // A drop target only exists while grouping by group: a file is not a place a
  // connection can be put, and the move API takes a group or a path.
  function accepts(target: string): boolean {
    return grouping === "groups" && dragging !== null && canDrop(dragging, target, groupNames);
  }
```

Give the heading its drop behaviour. Replace the `<h2>` with:

```tsx
            <h2
              draggable={grouping === "groups" && section.title !== ungrouped}
              onDragStart={(event) =>
                section.title === ungrouped
                  ? undefined
                  : startDrag(event, { kind: "group", name: section.title })
              }
              onDragEnd={() => setDragging(null)}
              onDragOver={(event) => {
                const target = section.title === ungrouped ? "" : section.title;
                if (!accepts(target)) return;
                // Only this call makes a drop possible at all.
                event.preventDefault();
                event.dataTransfer.dropEffect = "move";
              }}
              onDrop={(event) => {
                const target = section.title === ungrouped ? "" : section.title;
                if (!accepts(target) || dragging === null) return;
                event.preventDefault();
                onDrop(dragging, target);
                setDragging(null);
              }}
              className={`text-xs font-semibold uppercase tracking-wide ${
                accepts(section.title === ungrouped ? "" : section.title)
                  ? "rounded bg-zinc-800 text-zinc-200 outline outline-1 outline-zinc-600"
                  : "text-zinc-500"
              }`}
            >
              {section.title === ungrouped ? t("tree.ungrouped") : section.title}
            </h2>
```

Make the connection row a drag source. On the `<button>` that renders a host
with a concrete alias, add:

```tsx
                        draggable={grouping === "groups"}
                        onDragStart={(event) =>
                          startDrag(event, {
                            kind: "connection",
                            path: item.host.identity.path,
                            alias: item.host.identity.alias,
                            group: item.group,
                          })
                        }
                        onDragEnd={() => setDragging(null)}
```

Leave the pattern-rule branches alone. A block with no concrete alias cannot be
addressed by the move API, so it is not a drag source.

- [ ] **Step 4: Run the tests**

```
cd web && npx vitest run src/connections/ConnectionTree.test.tsx
```

Expected: PASS.

- [ ] **Step 5: Typecheck**

```
cd web && npx tsc -b
```

Expected: no error other than the pre-existing `@playwright/test` resolution
failures under `e2e/`.

- [ ] **Step 6: Commit**

```bash
git add web/src/connections/ConnectionTree.tsx web/src/connections/ConnectionTree.test.tsx
git commit -m "Drag a connection or a group onto a heading"
```

---

### Task 5: The page turns a drop into a request

**Files:**
- Modify: `web/src/connections/ConnectionsPage.tsx`
- Test: `web/src/connections/ConnectionsPage.test.tsx`

**Interfaces:**
- Consumes: `onDrop(payload, target)` from Task 4; `configApi.renameGroup(from, to)`
  and `configApi.file(path)`, both of which already exist.
- Produces: nothing later tasks use.

- [ ] **Step 1: Write the failing test**

Append to `web/src/connections/ConnectionsPage.test.tsx`, reusing the file's
existing helpers for the API double and rendering:

```tsx
describe("dropping in the tree", () => {
  it("moves a connection into a group", async () => {
    const api = buildConfigApi();
    renderPage(api);
    await screen.findByRole("button", { name: /nas/ });

    fireEvent.dragStart(screen.getByRole("button", { name: /nas/ }), { dataTransfer: transfer({ kind: "connection", path: "connections/home/nas.conf", alias: "nas", group: "home" }) });
    fireEvent.drop(screen.getByRole("heading", { name: "work" }), { dataTransfer: transfer({ kind: "connection", path: "connections/home/nas.conf", alias: "nas", group: "home" }) });

    await waitFor(() =>
      expect(api.save).toHaveBeenCalledWith(
        expect.objectContaining({ kind: "move", alias: "nas", destinationGroup: "work" }),
      ),
    );
  });

  it("nests a group by renaming it under its new parent", async () => {
    const api = buildConfigApi();
    renderPage(api);
    await screen.findByRole("heading", { name: "work" });

    fireEvent.dragStart(screen.getByRole("heading", { name: "work" }), { dataTransfer: transfer({ kind: "group", name: "work" }) });
    fireEvent.drop(screen.getByRole("heading", { name: "home" }), { dataTransfer: transfer({ kind: "group", name: "work" }) });

    await waitFor(() => expect(api.renameGroup).toHaveBeenCalledWith("work", "home/work"));
  });

  it("takes a group back to the top level", async () => {
    const api = buildConfigApi();
    renderPage(api);
    await screen.findByRole("heading", { name: "home/eu" });

    fireEvent.dragStart(screen.getByRole("heading", { name: "home/eu" }), { dataTransfer: transfer({ kind: "group", name: "home/eu" }) });
    fireEvent.drop(screen.getByRole("heading", { name: "Ungrouped" }), { dataTransfer: transfer({ kind: "group", name: "home/eu" }) });

    await waitFor(() => expect(api.renameGroup).toHaveBeenCalledWith("home/eu", "eu"));
  });
});
```

The third test needs `home/eu` among the declared groups in whatever overview
fixture the file uses; add it there.

Copy the `transfer` helper from `ConnectionTree.test.tsx` rather than importing
it across test files.

- [ ] **Step 2: Run the test and watch it fail**

```
cd web && npx vitest run src/connections/ConnectionsPage.test.tsx
```

Expected: FAIL — `onDrop` is a required prop that is not passed.

- [ ] **Step 3: Handle the drop**

In `web/src/connections/ConnectionsPage.tsx`, add:

```tsx
  // A drop is one of the moves this page already performs, chosen by what was
  // dragged. Nothing new reaches the server: a connection is a move, and a
  // group changing parent is a rename to a new path.
  async function onTreeDrop(payload: DragPayload, target: string) {
    try {
      if (payload.kind === "group") {
        const base = payload.name.slice(payload.name.lastIndexOf("/") + 1);
        const result = await configApi.renameGroup(payload.name, target === "" ? base : `${target}/${base}`);
        setPreview(result.preview);
        setProblem(null);
        await reload();
        return;
      }
      const file = await configApi.file(payload.path);
      if (target !== "") {
        await submit({
          kind: "move",
          path: payload.path,
          base: file.contents,
          alias: payload.alias,
          destinationGroup: target,
        }, false);
        return;
      }
      const destination = await configApi.file("config");
      await submit({
        kind: "move",
        path: payload.path,
        base: file.contents,
        alias: payload.alias,
        destinationPath: "config",
        destinationBase: destination.contents,
      }, false);
    } catch (error) {
      setPreview(null);
      setProblem(toProblem(error));
    }
  }
```

Import the payload type at the top of the file:

```tsx
import type { DragPayload } from "./dragdrop";
```

Pass the handler to the tree:

```tsx
        <ConnectionTree
          overview={overview}
          selected={selection}
          onSelect={onSelect}
          onOpenPatternRule={onOpenFile}
          onDrop={(payload, target) => void onTreeDrop(payload, target)}
        />
```

A dragged connection is not necessarily the selected one, so its file's bytes
are read here rather than taken from `detail`, and `submit` is called with
`reselect` false so the selection is left where the user put it.

- [ ] **Step 4: Run the tests**

```
cd web && npx vitest run src/connections
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add web/src/connections/ConnectionsPage.tsx web/src/connections/ConnectionsPage.test.tsx
git commit -m "Turn a drop into the move it means"
```

---

### Task 6: End to end, and the shipped bundle

**Files:**
- Modify: `web/e2e/connections.spec.ts`
- Modify: `internal/ui/dist/**` (build artefact)

**Interfaces:**
- Consumes: everything above.
- Produces: nothing.

- [ ] **Step 1: Write the end-to-end specification**

Append to `web/e2e/connections.spec.ts`, following the file's existing setup for
building an installation and opening the page:

```ts
test("moves a connection into a group by dragging it", async ({ page, installation }) => {
  await openSection(page, "Groups");
  await page.getByLabel("New group name").fill("work");
  await page.getByRole("button", { name: "Add group" }).click();
  expect(await clickAndAwait(page, "Save groups", "/api/v1/config/save")).toBe(200);

  await openSection(page, "Connections");
  const row = page.getByRole("button", { name: /bastion/ });
  const target = page.getByRole("heading", { name: "work" });
  await row.dragTo(target);

  // The connection is read back from the group's directory, which is what
  // proves the Include reaches it rather than that a file was merely written.
  await expect(page.getByRole("heading", { name: "work" })).toBeVisible();
  const entry = await installation.read("connections/work/config.conf");
  expect(entry).toContain("Host bastion");
});
```

Read the file's existing tests first and match their fixture and helper names
exactly; the names above are the ones used elsewhere in the suite as of this
plan, and the file is the authority.

- [ ] **Step 2: Rebuild the embedded bundle**

`internal/ui/dist` is a committed artefact that the binary embeds. A change to
`web/src` without a rebuild ships an old interface, and the end-to-end job
checks for exactly that.

```bash
make build
```

- [ ] **Step 3: Run the whole gate**

```bash
go test ./... && go test -race ./... && gofmt -l ./cmd ./internal
npm test --prefix web
cd web && npx tsc -b
```

Expected: Go unchanged and passing, web tests passing, typecheck clean apart from
the pre-existing `@playwright/test` resolution failures.

- [ ] **Step 4: Confirm nothing was added**

```bash
git diff --stat package.json web/package.json web/package-lock.json go.mod go.sum api/openapi.yaml
```

Expected: empty. A change here means the plan was not followed.

- [ ] **Step 5: Commit**

```bash
git add web/e2e/connections.spec.ts internal/ui/dist
git commit -m "Drive the drag against the built binary"
```

---

## Self-review

**Spec coverage.** Each row of the spec's operation table is covered: connection
into a group and connection out of a group by Tasks 4 and 5, group nesting and
un-nesting by the same. The spec's refusal list is Task 3, one test per entry.
The empty-group problem is Task 2. The keyboard repair is Task 1. The mechanism
section — private MIME type, state-held payload, `preventDefault` on `dragOver`
— is Task 4 Step 3. The testing section maps to Tasks 3–6.

**Not covered, deliberately.** The spec's boundaries section lists what is not
built (reordering, multi-select, touch, auto-scroll); no task builds them.

**Type consistency.** `DragPayload` is defined once in Task 3 and imported by
Tasks 4 and 5. `canDrop(payload, target, groups)` keeps that signature in both
callers. `onDrop(payload, target)` is declared in Task 4 and supplied in Task 5.
The empty string means "no group" in every one of them.
