# The Visual Language On Every Screen — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put the layout language from `2026-08-06-visual-language-design.md` on the nine screens that only got its colours, so the application has one shape and not ten.

**Architecture:** `ui/surface.tsx` already holds `Card`, `Row`, `Notice`, `Button` and `Segmented`, and `ui/Inspector.tsx` holds the right-hand pane. Only Connections renders any of them. Each remaining screen is one of two shapes — a settings form, or a list of things you act on — and each shape has one prescription. Nothing new is invented here; this is application.

**Tech Stack:** React 19.2.8, TypeScript 5.9.3, Tailwind CSS 4.3.3, Vitest 4.1.1, Playwright.

**Workspace:** `.worktrees/visual-language`, branch `feature/visual-language-screens`, cut from `26d7235`. The main checkout is in use by other work; nothing in this plan touches it. Run the end-to-end suite from `<worktree>/web` with `PLAYWRIGHT_BROWSERS_PATH=/Users/aida/projects/ssh-ui/web/.playwright-browsers`, because the harness resolves the binary as `../bin/ssh-ui` from the working directory.

## Global Constraints

- **`web/src/ui/palette.test.ts` must stay green.** It fails on any `bg-*`, `text-*`, `border-*` … naming a Tailwind palette, and names the file and line. It exists because ten literals survived a sweep whose grep listed four palettes and not `red`.
- **No component may contain a `dark:` variant.** The two themes differ only in the twenty tokens in `index.css`.
- **The accent is one action per screen.** Amber is a notice, red is a failure or a destructive act, green is the live session. Nothing else is coloured.
- **Accessible names and roles do not change.** The suite selects by `getByRole`, `getByLabel` and `getByText`; a caption may move but must keep its words. Where a caption has to change, its message key changes with it and both catalogues are updated.
- **Never add an `<h2>`–`<h6>` whose name contains a section name.** Playwright matches accessible names by substring, so an `<h2>` reading `鍵とホスト` makes `bootstrap.spec.ts:164`'s query for the level-2 heading `鍵` match twice. The shell's own section label is deliberately not a heading for this reason.
- Every message added to `web/src/i18n/messages.ts` goes into **both** catalogues; `ja` is typed as a complete record of `en`.
- `internal/ui/dist` is a committed bundle: every task ends with `make build` before its commit.
- Verification per task: `npm run typecheck --prefix web`, `npm test --prefix web`, and the end-to-end suite as described under Workspace.

## The two shapes

**A settings form** — a stack of captioned controls that describe one thing.
Prescription: a `Card` per group of related settings, one `Row` per setting, the group's explanation under the card rather than between the rows. Multi-line controls (a textarea, a key body) stay stacked, because a caption beside a three-line box reads as a caption for the gap beneath it. The screen's one primary action is the only accent.

**A list of things you act on** — a list where each item carries its own editing controls.
Prescription: the list becomes rows that say what each item *is*. What you do *to* an item moves to the inspector, which opens for the selected item. Actions that make a new item move to the toolbar. This is what Connections already does, and the pane and the toolbar slot already exist for it.

## Screen assignment

| Screen | Shape | Notes |
| --- | --- | --- |
| Remote Keys | form | Writes its own `<label>` and raw inputs; uses neither `Field` nor `control`. |
| Sync | form | Already uses `Field` and `sectionCard`; the closest to done. |
| Secrets | form | Two lists of stored secrets sit inside it; they become rows, not an inspector — you delete a secret, you do not edit one. |
| Diagnostics | form | One alias field and a column of results. Results become a card of rows. |
| Config Explorer | list | The Include hierarchy is the list; the file view is the detail. Already two panes in spirit. |
| Known Hosts | list | Scan controls to the toolbar; the entries become rows; delete confirmation becomes a `Notice tone="danger"`. |
| History | list | Two lists, no editing. Rows only; no inspector. |
| Groups | list | The heaviest: seven controls per group, permanently expanded. Editing moves to the inspector. |
| Keys | list | The largest file, 23 buttons. Same treatment as Groups, done last because it is the biggest. |

## Order

Smallest first, so the pattern is established on a screen where a mistake is cheap, and the two large list screens come last when the shape is proven: Remote Keys, Sync, Diagnostics, Secrets, History, Known Hosts, Config Explorer, Groups, Keys.

## Acceptance, per screen

Each screen's task is complete when all of these hold:

- [ ] `npm test --prefix web` passes, including `palette.test.ts`
- [ ] `npm run typecheck --prefix web` passes
- [ ] the end-to-end suite passes
- [ ] `grep -c "<Card" web/src/<screen>` is at least 1, or the screen is a list whose items are rows
- [ ] no `<label className=` writing its own control styling remains in the file — captions come from `Row`, `Field` or `fieldLabel`
- [ ] the screen has at most one `primaryAction` / `<Button kind="primary">` visible at a time
- [ ] both appearances render it: `e2e/appearance.spec.ts` already walks all ten sections in light and dark

---

### Task 1: Use the Notice component, or delete it

`Notice` has been in `ui/surface.tsx` since it was written and is rendered nowhere. Every panel writes its own `<p role="alert" className="text-sm text-danger">` instead — there are eleven of them.

**Files:** `web/src/ui/surface.tsx`, and the panels listed by the grep in step 1.

- [ ] **Step 1: Find every hand-written alert and status line**

Run: `grep -rn 'role="alert"\|role="status"' web/src --include='*.tsx' | grep -v test | grep -v ui/surface`
Expected: a list of panels writing the same two shapes by hand.

- [ ] **Step 2: Replace them with `Notice`**

An error becomes `<Notice tone="danger">{message}</Notice>`; an amber caution becomes `<Notice>{message}</Notice>`. `Notice` already renders `role="alert"` for danger and `role="status"` otherwise, so no test selector moves.

Leave alone: the shell's session status in `App.tsx` (it is the banner's own live region, and the suite scopes to it), and `aria-live="polite"` paragraphs that are not alerts.

- [ ] **Step 3: Verify and commit**

```bash
npm run typecheck --prefix web && npm test --prefix web
make build
git add web/src internal/ui/dist
git commit -m "Say a failure the same way on every screen"
```

---

### Tasks 2–10: One per screen, in the order above

Each screen is its own task and its own commit. The work is the same shape every time:

- [ ] **Step 1: Read the screen's render function** before changing anything. Note which captions exist, because they are accessible names the suite may address.
- [ ] **Step 2: Apply the prescription for its shape** from "The two shapes" above.
- [ ] **Step 3: Run the unit suite and read every failure.** A failure naming a caption means a name moved; either put it back or move the test with it deliberately.
- [ ] **Step 4: Run the end-to-end suite.**
- [ ] **Step 5: Check the acceptance list** for that screen.
- [ ] **Step 6: `make build` and commit the screen on its own.**

The per-screen specifics are deliberately not written out here. Each screen's render function has to be read first, and a plan that guessed at their contents would be inventing steps rather than recording them — the previous plan's Task 10 said "six components" where there were fourteen, because it counted from a grep instead of from the files.

---

## Self-Review

**Spec coverage.** The design document asks for one palette (done, and now enforced by a test), one set of components, and an inspector that other screens can fill. This plan spends the components and gives the inspector its second and third users.

**What this plan does not do.** It does not merge, rename or remove a section; it does not change an API; it adds no capability. If a screen's behaviour looks wrong while converting it, that is a separate change and a separate commit.

**The known risk.** Moving a control from a panel into the inspector changes where a test has to look for it, exactly as it did for the connection's colour and tags. Every screen's task therefore ends by running the end-to-end suite, not only the unit tests.
