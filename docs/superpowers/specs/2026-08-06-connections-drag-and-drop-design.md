# Connections: moving by drag and drop

Moving a connection into a group takes four interactions today — select the
connection, find the group select in the host detail, choose, press the button —
and re-nesting a group takes typing its new path into the Groups panel. Both are
"put this thing there", and both read as filling in a form.

This adds dragging as a second way to do them. It adds no server code and no
dependency.

## What can be dragged where

Only while the tree is grouping by group. The by-file view has no drop targets:
a file is not a place a connection can be put, and the move API takes a group or
a path, not a file the user pointed at.

| Dragged | Dropped on | Result |
| --- | --- | --- |
| a connection | a group heading | the connection moves into that group |
| a connection | the "no group" heading | the connection moves back into `~/.ssh/config` |
| a group heading | another group heading | the group is nested inside it |
| a group heading | the "no group" heading | the group returns to the top level |

Nothing else is draggable. A pattern rule — a `Host` block whose line carries no
concrete alias — is not: the move API addresses a block by alias, and such a
block has none. The tree already routes those rows to the file view for the same
reason.

## The server does not change

Every drop is a request that already exists, with a shape the page already
builds elsewhere.

| Drop | Request |
| --- | --- |
| connection → group | `POST /api/v1/config/save` `{kind: "move", path, base, alias, destinationGroup}` |
| connection → no group | `POST /api/v1/config/save` `{kind: "move", path, base, alias, destinationPath: "config", destinationBase}` |
| group → group | `POST /api/v1/config/groups/rename` `{from, to: "<parent>/<basename>"}` |
| group → no group | `POST /api/v1/config/groups/rename` `{from, to: "<basename>"}` |

The first is what the host detail's "Move to group" button sends. The second is
what `moveHost` in `ConnectionsPage` already sends for a file-to-file move, and
needs `configApi.file("config")` first to carry the destination's bytes as its
precondition. The last two are what the Groups panel's rename field sends.

A drop writes immediately, like the button it duplicates. It is not previewed
first. The save's diff appears where every other save's diff appears, and an
unwanted move is undone from History, which keeps a generational backup of every
file the transaction touched.

## Drops the interface will not offer

A drop target is refused before the drag begins when the server would refuse it
after. This is convenience, not safety: the server remains the only guard, and
its refusal still arrives as a problem and is shown by the page's existing
handler.

- a connection onto the group it is already in — nothing to do
- a group onto itself
- a group already at the top level onto the "no group" heading — nothing to do
- a group onto one of its own descendants — `ErrGroupSelfNesting`
- a group onto a parent that already holds a group of that name — `ErrGroupExists`
- a nesting that would take the name past six segments — `ErrInvalidGroupName`,
  which exists because the key scanner walks at most eight directories down and a
  key in a seventh group segment would vanish from the inventory
- anything at all while grouping by file

All of these are decided from the dragged item and the declared group list, which
the tree already holds in `overview.metadata.groups`.

## A group with nothing in it has to be visible

`ConnectionTree.tsx:135` renders nothing for a section with no items. A group
becomes invisible the moment its last connection leaves it — so dragging the
last connection out of a group would destroy the only thing you could drag it
back onto.

Declared groups are therefore rendered whether or not they hold anything. This
is a change to the tree that stands on its own: a group created in the Groups
panel is currently absent from Connections until something is put in it, which
gives no sign that the creation worked.

An empty group renders its heading and, beneath it, a line saying it is empty. A
group that is declared but whose directory is missing is not special-cased here;
the overview already reports that separately.

## Keyboard

No parallel keyboard dragging is built. Dragging is a second way to reach two
operations that already have keyboard paths, and it does not become the only way
to reach either:

- a connection moves by the host detail's group select and its button
- a group re-nests by the Groups panel's rename field, which takes a path, so
  `client-a/work` nests `work` under `client-a`

One repair is needed to keep that true. The host detail's button is disabled
when the select reads "no group" (`HostDetail.tsx:357`), so **there is no
keyboard path for taking a connection out of a group at all** — the drag would
be the only way, which this codebase's own standards do not allow. The button is
changed to accept the empty choice and send the `destinationPath: "config"`
form. That closes a gap that exists today independently of dragging.

## Mechanism

Native HTML5 drag events. No dependency is added.

The interaction is one item onto one heading. There is no sorting, no reordering
within a list, no collision detection and no touch target — the application is a
localhost page driven by a desktop browser. A drag-and-drop library would carry
all of that to serve none of it, and this repository records the reason for every
dependency it has.

The dragged row sets `draggable` and, on `dragStart`, does two things: it writes
the payload to `dataTransfer` under a private MIME type, and it puts the same
payload into React state.

The state copy is what decides the drop targets, and it is not redundant. A
`dragover` handler may read `dataTransfer.types` but not `getData` — the data is
protected until the drop — so a target cannot inspect what is being dragged in
order to decide whether to accept it. Deciding from component state is the way
this is done; the private type on `dataTransfer` is then only used to tell one of
these drags from a drag that started outside the page, which `types` can answer.

The payload is one of:

```
{ kind: "connection", path: string, alias: string }
{ kind: "group", name: string }
```

A heading calls `preventDefault` on `dragOver` only when the state says the drag
is one it accepts, since that call is what makes a drop possible at all. The
state is cleared on `dragEnd`, including a drag abandoned outside the window.

## Boundaries

- Dragging changes where a connection or a group lives. It never changes
  display order: that is `order` in `metadata.json` and a separate feature.
- One item at a time. No multi-select.
- A drop that the server refuses leaves both files exactly as they were,
  because the refusal happens before anything is staged — that is the
  transaction's property, not this feature's.
- Moving a connection into `~/.ssh/config` appends its block to the end of that
  file. It does not return to the position it was in before it was grouped,
  because the move carries the block and not its former surroundings.

## Testing

- `ConnectionTree.test.tsx`: which targets accept a drop and which refuse, for
  each refusal above, and that a drop calls back with the payload it was given.
  jsdom dispatches `dragStart`, `dragOver` and `drop` through `fireEvent`, and
  `dataTransfer` is supplied as a stub, so no browser is needed.
- `ConnectionTree.test.tsx`: a declared group with no connections renders its
  heading.
- `ConnectionsPage.test.tsx`: each of the four drops produces the request in the
  table above, with the destination base read first where one is needed.
- `HostDetail.test.tsx`: the group button is enabled for the empty choice and
  sends the ungrouping form.
- `web/e2e/connections.spec.ts`: one specification dragging a connection into a
  group against the built binary, using Playwright's `dragTo`.

No Go test is added, because no Go code changes.
