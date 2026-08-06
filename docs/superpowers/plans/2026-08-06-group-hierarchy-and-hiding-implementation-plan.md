# Group hierarchy and hiding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Render the connections tree as the hierarchy the group names already describe, let a group that only contains groups be hidden from it, and make a whole group block a drop target.

**Architecture:** `ConnectionTree` builds a tree from the declared names instead of a flat list, and renders each node recursively. `hidden` joins the presentation fields in `GroupMetadata`; the Groups panel offers it, and refuses it while the group holds connections of its own. The drop handlers move from the heading to the section and stop propagating so the innermost claim wins.

**Tech Stack:** Go 1.26.5, React 19.2.8, TypeScript 5.9.3, Vitest 4.1.1, Playwright 1.62.1. No new dependency.

## Global Constraints

- No new npm or Go dependency; `go.mod`, `go.sum`, `web/package.json` and `web/package-lock.json` unchanged.
- `api/openapi.yaml` is the single source for both `internal/api/models.gen.go` and `web/src/api/schema.d.ts`. Run `make generate` after editing it; never hand-edit a generated file. `make verify-generated` must stay clean.
- Every user-visible string goes through `useTranslate` and is added to **both** locale blocks in `web/src/i18n/messages.ts`.
- `internal/ui/dist` is committed. Run `make build` before the final commit.
- Hiding changes the connections tree and nothing else: no Include line, no group directory, no `ssh -G` answer.

---

### Task 1: `hidden` reaches the metadata document

**Files:**
- Modify: `api/openapi.yaml` (`GroupMetadata`)
- Modify: `internal/application/metadata.go:92-98`
- Generated: `internal/api/models.gen.go`, `web/src/api/schema.d.ts` (via `make generate`)
- Test: `internal/application/metadata_test.go`

**Interfaces:**
- Produces: `GroupMetadata.Hidden bool` in Go with `json:"hidden,omitempty"`, and
  `hidden?: boolean` in the TypeScript schema. Tasks 2 and 4 read it.

- [ ] **Step 1: Write the failing test**

```go
// Hidden is presentation, like colour and order: this engine carries it and
// never acts on it. A field the server dropped would be a setting that
// un-set itself on the next save of anything else.
func TestGroupMetadataCarriesTheHiddenFlagThroughARoundTrip(t *testing.T) {
	workspace := newTestWorkspace(t)
	store := NewMetadataStore(workspace)

	metadata := NewMetadata()
	metadata.Groups = []GroupMetadata{{Name: "dubguild", Hidden: true}, {Name: "dubguild/mdx"}}
	change, precondition, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	_ = change
	written, err := store.Change(metadata, precondition)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(written.Contents), `"hidden": true`) {
		t.Errorf("written metadata = %s, want the hidden flag", written.Contents)
	}
}
```

Read the existing tests in that file first and match how they build a store and
call `Load`/`Change`; the shape above is the API as of this plan and the file is
the authority.

- [ ] **Step 2: Run it and watch it fail**

```
go test ./internal/application/ -run TestGroupMetadataCarriesTheHiddenFlag
```

Expected: FAIL — `Hidden` is not a field.

- [ ] **Step 3: Add the field to the contract**

In `api/openapi.yaml`, in `GroupMetadata`'s properties, after `order`:

```yaml
        # Presentation only. A group whose purpose is to contain other groups
        # has nothing of its own to show in the connections tree, and this takes
        # its heading out of it. Nothing OpenSSH reads changes.
        hidden: { type: boolean }
```

- [ ] **Step 4: Add the field to the Go type**

In `internal/application/metadata.go`:

```go
type GroupMetadata struct {
	Name   string `json:"name"`
	Colour string `json:"colour,omitempty"`
	Note   string `json:"note,omitempty"`
	Order  int    `json:"order,omitempty"`
	// Hidden takes the group's own heading out of the connections tree. It is
	// presentation, like Colour and Order: this engine carries it and never
	// reads it.
	Hidden   bool      `json:"hidden,omitempty"`
	Settings []Setting `json:"settings,omitempty"`
}
```

- [ ] **Step 5: Regenerate and verify**

```
make generate && make verify-generated
go test ./internal/application/ -run TestGroupMetadataCarriesTheHiddenFlag
```

Expected: the generated files change, `verify-generated` is clean afterwards,
and the test passes.

- [ ] **Step 6: Commit**

```bash
git add api/openapi.yaml internal/application/metadata.go internal/application/metadata_test.go \
        internal/api/models.gen.go web/src/api/schema.d.ts
git commit -m "Carry a hidden flag for a group"
```

---

### Task 2: The Groups panel offers hiding, and refuses it where it would hide a connection

**Files:**
- Modify: `web/src/groups/GroupsPanel.tsx` (beside the colour and order controls, near line 312)
- Modify: `web/src/i18n/messages.ts`
- Test: `web/src/groups/GroupsPanel.test.tsx`

**Interfaces:**
- Consumes: `GroupMetadata.hidden` from Task 1; the panel's existing
  `updateGroup(name, patch)` and `membersOf(name)`.
- Produces: nothing later tasks call.

- [ ] **Step 1: Write the failing test**

Append to `web/src/groups/GroupsPanel.test.tsx`, matching the file's existing
helpers for building an overview and rendering:

```tsx
describe("hiding a group from the connections tree", () => {
  it("offers it for a group that holds no connections of its own", async () => {
    const user = userEvent.setup();
    renderPanel(/* an overview where "work" holds nothing directly */);

    const toggle = await screen.findByLabelText("Hide work from Connections");
    expect(toggle).toBeEnabled();
    await user.click(toggle);

    expect(toggle).toBeChecked();
  });

  it("refuses it for a group that holds connections, and says why", async () => {
    renderPanel(/* an overview where "home" holds nas */);

    expect(await screen.findByLabelText("Hide home from Connections")).toBeDisabled();
    expect(screen.getByText(/holds connections of its own/)).toBeInTheDocument();
  });
});
```

Read the file first; reuse whatever it already has for building the overview
double rather than inventing a new one.

- [ ] **Step 2: Run it and watch it fail**

```
cd web && npx vitest run src/groups/GroupsPanel.test.tsx
```

Expected: FAIL — no such control.

- [ ] **Step 3: Add the strings**

`web/src/i18n/messages.ts`, English block beside the other `groups.` keys:

```ts
  "groups.hide": "Hide {name} from Connections",
  "groups.hideShort": "Hide from Connections",
  "groups.hideOnlyContainers":
    "This group holds connections of its own, so hiding it would hide them. Move them into a child group first.",
```

Japanese block:

```ts
  "groups.hide": "{name} を接続タブで非表示",
  "groups.hideShort": "接続タブで非表示",
  "groups.hideOnlyContainers":
    "このグループは直下に接続を持っています。非表示にするとその接続まで見えなくなるため、先に子グループへ移してください。",
```

- [ ] **Step 4: Add the control**

In `web/src/groups/GroupsPanel.tsx`, inside the same `div` that carries the
colour and order controls:

```tsx
                {/*
                  Hiding is for a group whose purpose is to hold other groups.
                  A group with connections of its own would take them out of
                  view with it, so the control is refused there rather than
                  quietly doing nothing.
                */}
                <label htmlFor={`group-hidden-${group.name}`} className="flex flex-col gap-1">
                  <span className={fieldLabel}>{t("groups.hideShort")}</span>
                  <input
                    id={`group-hidden-${group.name}`}
                    type="checkbox"
                    aria-label={t("groups.hide", { name: group.name })}
                    checked={group.hidden === true}
                    disabled={membersOf(group.name).length > 0}
                    onChange={(event) => updateGroup(group.name, { hidden: event.target.checked })}
                    className="size-4"
                  />
                </label>
```

and, directly under that `div`, the reason when it is refused:

```tsx
              {membersOf(group.name).length > 0 ? (
                <p className={hintText}>{t("groups.hideOnlyContainers")}</p>
              ) : null}
```

Check what `hintText` is imported as in this file; use whatever it already uses
for a hint.

- [ ] **Step 5: Run the tests**

```
cd web && npx vitest run src/groups
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add web/src/groups web/src/i18n/messages.ts
git commit -m "Offer to hide a group that only holds groups"
```

---

### Task 3: The tree is a tree

**Files:**
- Modify: `web/src/connections/ConnectionTree.tsx`
- Test: `web/src/connections/ConnectionTree.test.tsx`

**Interfaces:**
- Consumes: nothing new.
- Produces: nothing later tasks call. Task 4 edits the same render.

- [ ] **Step 1: Write the failing test**

Append to `web/src/connections/ConnectionTree.test.tsx`:

```tsx
describe("the group hierarchy", () => {
  const nested: Overview = {
    ...overview,
    hosts: [
      { ...nas, identity: { path: "connections/work/eu/lon.conf", alias: "lon" },
        file: { path: "connections/work/eu/lon.conf", absolute: "/home/tester/.ssh/connections/work/eu/lon.conf" },
        group: "work/eu" },
    ],
    metadata: { ...overview.metadata, groups: [{ name: "work" }, { name: "work/eu" }] },
  };

  it("draws a child group inside its parent, not beside it", () => {
    render(<ConnectionTree overview={nested} selected={null} onSelect={vi.fn()} onOpenPatternRule={vi.fn()} onDrop={vi.fn()} />);

    const parent = screen.getByRole("region", { name: "work" });
    expect(within(parent).getByRole("heading", { name: "work/eu" })).toBeInTheDocument();
  });

  it("shows a child group's name by its own segment", () => {
    render(<ConnectionTree overview={nested} selected={null} onSelect={vi.fn()} onOpenPatternRule={vi.fn()} onDrop={vi.fn()} />);

    expect(screen.getByRole("heading", { name: "work/eu" })).toHaveTextContent("eu");
  });

  it("collapses a parent, taking its children with it", async () => {
    const user = userEvent.setup();
    render(<ConnectionTree overview={nested} selected={null} onSelect={vi.fn()} onOpenPatternRule={vi.fn()} onDrop={vi.fn()} />);

    await user.click(screen.getByRole("button", { name: "Collapse work" }));

    expect(screen.queryByRole("heading", { name: "work/eu" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /lon/ })).not.toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run it and watch it fail**

```
cd web && npx vitest run src/connections/ConnectionTree.test.tsx
```

Expected: FAIL — no region named `work`, headings are flat.

- [ ] **Step 3: Add the strings**

English:

```ts
  "tree.collapse": "Collapse {name}",
  "tree.expand": "Expand {name}",
```

Japanese:

```ts
  "tree.collapse": "{name} を折りたたむ",
  "tree.expand": "{name} を展開する",
```

- [ ] **Step 4: Build the tree and render it recursively**

Replace the flat `sections` memo with a node tree, and the flat map with a
recursive renderer. The group node type:

```tsx
type GroupNode = {
  // The full declared name, which is what every callback and every drop target
  // uses. The heading shows only the last segment, because the rest is the path
  // the reader has already walked.
  name: string;
  label: string;
  items: typeof decorated;
  children: GroupNode[];
};
```

Build it from the declared names, deepest last, so a child is attached to the
nearest declared ancestor. A group whose parent is not declared is a root: an
undeclared parent is not a group, and inventing one here would show a heading
for something no Include line names.

Render a node as a `<section aria-label={node.name}>` holding the heading, the
disclosure control when it has children, its own items, and its children. Give
the children a left padding so depth is visible.

Keep the by-file mode exactly as it is: files have no hierarchy.

- [ ] **Step 5: Run the tests**

```
cd web && npx vitest run src/connections/ConnectionTree.test.tsx
```

Expected: PASS, including every test that was already there.

- [ ] **Step 6: Commit**

```bash
git add web/src/connections/ConnectionTree.tsx web/src/connections/ConnectionTree.test.tsx \
        web/src/i18n/messages.ts
git commit -m "Draw the group tree as the names already describe it"
```

---

### Task 4: A hidden group loses its heading and keeps its children

**Files:**
- Modify: `web/src/connections/ConnectionTree.tsx`
- Test: `web/src/connections/ConnectionTree.test.tsx`

**Interfaces:**
- Consumes: `hidden` from Task 1, the node tree from Task 3.

- [ ] **Step 1: Write the failing test**

```tsx
describe("a hidden group", () => {
  const container: Overview = {
    ...overview,
    hosts: [
      { ...nas, identity: { path: "connections/work/eu/lon.conf", alias: "lon" },
        file: { path: "connections/work/eu/lon.conf", absolute: "/home/tester/.ssh/connections/work/eu/lon.conf" },
        group: "work/eu" },
    ],
    metadata: { ...overview.metadata, groups: [{ name: "work", hidden: true }, { name: "work/eu" }] },
  };

  it("loses its own heading", () => {
    render(<ConnectionTree overview={container} selected={null} onSelect={vi.fn()} onOpenPatternRule={vi.fn()} onDrop={vi.fn()} />);

    expect(screen.queryByRole("heading", { name: "work" })).not.toBeInTheDocument();
  });

  it("keeps its children, and the connections inside them", () => {
    render(<ConnectionTree overview={container} selected={null} onSelect={vi.fn()} onOpenPatternRule={vi.fn()} onDrop={vi.fn()} />);

    expect(screen.getByRole("heading", { name: "work/eu" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /lon/ })).toBeInTheDocument();
  });

  // The flag is ignored rather than merely un-settable in the panel, because
  // metadata.json is a file a user may edit by hand, and a heading that
  // vanished with connections under it is the failure this guards against.
  it("is drawn anyway while it holds connections of its own", () => {
    const withOwn: Overview = {
      ...container,
      hosts: [...container.hosts, { ...nas, group: "work" }],
    };
    render(<ConnectionTree overview={withOwn} selected={null} onSelect={vi.fn()} onOpenPatternRule={vi.fn()} onDrop={vi.fn()} />);

    expect(screen.getByRole("heading", { name: "work" })).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run it and watch it fail**

```
cd web && npx vitest run src/connections/ConnectionTree.test.tsx
```

Expected: FAIL — the heading is drawn.

- [ ] **Step 3: Skip the heading and promote the children**

In the recursive renderer, when a node is hidden and holds no items of its own,
render its children in its place at the same depth as the node itself, with no
heading and no section of its own.

- [ ] **Step 4: Run the tests**

```
cd web && npx vitest run src/connections
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add web/src/connections/ConnectionTree.tsx web/src/connections/ConnectionTree.test.tsx
git commit -m "Take a container group's heading out of the tree"
```

---

### Task 5: The whole block accepts a drop, innermost first

**Files:**
- Modify: `web/src/connections/ConnectionTree.tsx`
- Test: `web/src/connections/ConnectionTree.test.tsx`

- [ ] **Step 1: Write the failing test**

```tsx
it("accepts a drop anywhere in a group's block, not only on its heading", () => {
  const onDrop = renderTree();
  const payload: DragPayload = { kind: "connection", path: "connections/home/nas.conf", alias: "nas", group: "home" };

  fireEvent.dragStart(screen.getByRole("button", { name: /nas/ }), { dataTransfer: transfer(payload) });
  fireEvent.drop(screen.getByRole("region", { name: "work" }), { dataTransfer: transfer(payload) });

  expect(onDrop).toHaveBeenCalledWith(payload, "work");
});

// Sections nest now, so a drop inside a child reaches its parent too unless the
// child stops it. Which one won would otherwise be an accident of bubbling.
it("gives a drop in a child block to the child, not to its parent", () => {
  const onDrop = vi.fn();
  render(<ConnectionTree overview={nestedWithGroups} selected={null} onSelect={vi.fn()} onOpenPatternRule={vi.fn()} onDrop={onDrop} />);
  const payload: DragPayload = { kind: "connection", path: "connections/home/nas.conf", alias: "nas", group: "home" };

  fireEvent.dragStart(screen.getByRole("button", { name: /nas/ }), { dataTransfer: transfer(payload) });
  fireEvent.drop(screen.getByRole("region", { name: "work/eu" }), { dataTransfer: transfer(payload) });

  expect(onDrop).toHaveBeenCalledTimes(1);
  expect(onDrop).toHaveBeenCalledWith(payload, "work/eu");
});
```

Build `nestedWithGroups` in the describe block: an overview whose declared
groups are `home`, `work` and `work/eu`, with `nas` in `home`.

- [ ] **Step 2: Run it and watch it fail**

Expected: FAIL — the region is not a drop target.

- [ ] **Step 3: Move the handlers**

Move `onDragOver` and `onDrop` from the `<h2>` to the node's `<section>`, and
call `event.stopPropagation()` in both once the section has claimed the event,
so the innermost accepting section wins. Leave `draggable` and `onDragStart` on
the heading: a whole block that could be picked up would make picking up a
connection inside it ambiguous.

Highlight the whole section rather than the heading when it accepts.

- [ ] **Step 4: Run the tests**

```
cd web && npx vitest run src/connections
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add web/src/connections/ConnectionTree.tsx web/src/connections/ConnectionTree.test.tsx
git commit -m "Take a drop anywhere in a group's block"
```

---

### Task 6: End to end, and the shipped bundle

**Files:**
- Modify: `web/e2e/groups.spec.ts`
- Modify: `internal/ui/dist/**`

- [ ] **Step 1: Add the end-to-end case**

Append to `web/e2e/groups.spec.ts`, matching the file's existing helpers:

```ts
test("shows a nested group inside its parent in the connections tree", async ({ page, installation }) => {
  await page.goto(installation.url);
  await openSection(page, "Groups");
  for (const name of ["work", "work/eu"]) {
    await page.getByLabel("New group name").fill(name);
    await page.getByRole("button", { name: "Add group" }).click();
  }
  expect(await clickAndAwait(page, "Save groups", "/api/v1/config/save")).toBe(200);

  await openSection(page, "Connections");
  const parent = page.getByRole("region", { name: "work" });
  await expect(parent.getByRole("heading", { name: "work/eu" })).toBeVisible();
});
```

- [ ] **Step 2: Rebuild the embedded bundle**

```bash
make build
```

- [ ] **Step 3: Run the whole gate**

```bash
go test ./... && go test -race ./... && gofmt -l ./cmd ./internal
make verify-generated
npm test --prefix web
cd web && npx tsc -b
make e2e
```

- [ ] **Step 4: Confirm nothing was added**

```bash
git diff --stat origin/main -- web/package.json web/package-lock.json go.mod go.sum
```

Expected: empty.

- [ ] **Step 5: Commit**

```bash
git add web/e2e/groups.spec.ts internal/ui/dist
git commit -m "Drive the group tree against the built binary"
```

---

## Self-review

**Spec coverage.** The hierarchy is Task 3, collapse included. Hiding is Tasks 1,
2 and 4 — the field, the control with its refusal, and the rendering. The wider
drop target with innermost-wins is Task 5. The spec's boundaries — hiding
touches only the tree, the Groups panel and host detail still list every group —
are not separately implemented because no task changes those surfaces.

**Placeholders.** Two test bodies carry a comment where the fixture belongs
(`/* an overview where … */`) rather than the fixture itself, because the
panel's existing helper is the authority on how one is built and inventing a
second would be worse than pointing at it. Every other step carries its code.

**Type consistency.** `GroupMetadata.Hidden` / `hidden` is defined in Task 1 and
read in Tasks 2 and 4. `GroupNode` is defined in Task 3 and extended in Tasks 4
and 5. `onDrop(payload, target)` is unchanged from the existing tree.
