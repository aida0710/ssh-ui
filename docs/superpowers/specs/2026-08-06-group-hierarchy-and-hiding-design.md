# A group tree, and hiding a group that only contains groups

A group name carries its hierarchy — `work/eu` is inside `work` — and the
connections tree renders every group as a flat peer anyway. So a group made only
to hold other groups reads as an empty sibling of its own children, which is
what it is not.

This makes the tree a tree, and lets such a group be hidden from it.

## The tree

Sections are built from the declared group names rather than listed. Each group
renders its heading, then the connections whose own group is exactly that name,
then its child groups indented beneath. The ungrouped bucket stays where it is,
last and at the top level.

A group with children gets a disclosure control. **Collapse is not persisted.**
Writing it down would mean putting a momentary interface state into
`metadata.json`, next to the settings that describe the configuration; a tree
that opens fully on reload is the cheaper wrong.

## Hiding

`GroupMetadata` gains `hidden`. It is presentation, which is what that document
is for, and it changes nothing OpenSSH reads: the Include line, the group
directory and `ssh -G` are all untouched.

Hiding removes the group's own heading. Its children are drawn one level
shallower, in its place — nothing moves out of view, only the heading goes.

**The control is disabled while the group holds connections of its own**, and
the panel says why. A hidden group whose heading is gone would take its
connections with it, and this repository has spent enough of its life finding
things that exist and that nothing shows. The flag is also ignored in that state
rather than merely un-settable, because `metadata.json` is a file a user may
edit by hand.

## Dropping on the whole block

The drop target moves from the heading to the whole section, so anywhere in a
group's block accepts what the heading accepted.

Sections now nest, so a drop inside a child also reaches its parent. The
innermost section wins: `dragover` and `drop` stop propagating once a section
has claimed them. Without that, dropping into `work/eu` would also be a drop
into `work`, and which one won would be an accident of bubbling order.

The drag handle stays on the heading. A whole block that could be picked up
would make picking up a connection inside it ambiguous.

## What hiding costs

**A hidden group is not a drop target.** Its heading is gone, so there is
nowhere to drop, and a container group hidden from the tree cannot have a new
child dragged into it.

The keyboard routes are unaffected — the Groups panel's rename field takes a
path, so `dubguild/new` still nests, and the host detail's group select still
lists every declared group including hidden ones. Dragging simply stops being a
complete way to reach a hidden group, which is the price of not drawing it.

## Boundaries

- Hiding affects the connections tree and nothing else. The Groups panel lists
  every group, hidden or not; the host detail's select offers every group.
- A hidden group still declares its Include line and still reads its files.
- Collapse and hiding are different things: collapse is momentary and applies to
  any group with children, hiding is configuration and applies only to a group
  with no connections of its own.
- No change to how groups are declared, renamed, deleted or moved.

## Testing

- `ConnectionTree.test.tsx`: a child group renders inside its parent rather than
  beside it; a hidden group's heading is absent and its children are still
  there, one level shallower; a group holding connections is drawn even when
  the flag is set; collapsing a parent hides its children and its own
  connections; a drop anywhere in a block reaches the group; a drop in a child
  block does not also reach the parent.
- `GroupsPanel.test.tsx`: the hide control is disabled, with its reason shown,
  for a group holding connections, and enabled for one that holds none;
  toggling it writes `hidden` into the metadata that is saved.
- `web/e2e/groups.spec.ts`: a nested group appears under its parent in the tree.
- Go: `GroupMetadata.Hidden` survives a metadata round trip. Nothing else in Go
  changes — the field is carried, never read.
