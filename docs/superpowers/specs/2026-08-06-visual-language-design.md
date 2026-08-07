# A visual language, and the inspector it makes room for

Every screen in this application works and none of them agree on what anything
looks like. `index.css` is six lines. `ui/form.tsx` holds the shared controls,
nine panels use it, and ten more components write `border-zinc-700
bg-zinc-900` by hand. Nothing marks which of two things on a screen matters
more, because everything is the same grey.

This gives the application one palette, one set of components, and one rule
about colour. It changes no behaviour and adds no feature.

## Colour means something happened

**The accent is spent on the action that completes a section, and on nothing
else.** Not on the selected row, not on a selected tab, not on icons, not on
values, not on headings. A row that is merely selected was the strongest thing
on the screen; it now takes a grey fill and gives the colour back.

Per section, not per screen. Sync configures a bucket *and* pushes a snapshot;
Keys creates a key, registers one with the agent, moves one and changes one's
passphrase. Those are separate goals that happen to share a window, and the
button that completes each is that section's one accent.

The test is the outcome, not the count: **two accents must never lead to the
same result.** Where they did — a host could be given a password by pointing it
at a stored one or by storing a new one, and both buttons said only
"password" — the fault was the words, and naming the two acts apart fixed it
without taking the colour off either.

Two exceptions, deliberate: the focus ring on a control, and the tick in a
checked box. Both are transient, both are the accepted convention, and both
mark where the user is rather than what the screen is for.

What remains coloured is state, and only state:

| Colour | Means |
| --- | --- |
| Blue | The action that completes a section |
| Amber | A notice — this save rewrites three lines, this host has diagnostics |
| Red | An operation that destroys something |
| Green | The local session is alive |

Read the other way, the rule is the point: if something is coloured, something
has happened. An application that edits `~/.ssh` and can refuse a write needs
that sentence to be true, and it is not true when the chrome is also blue.

## Tokens

`index.css` gains about twenty named values, given twice — once for light and
once for dark — and exposed to Tailwind as utilities. Tailwind is 4.3.3, so
this is `@theme inline` over custom properties rather than a config file:

```css
:root            { --ui-card: #ffffff; --ui-accent: #007aff; ... }
[data-theme=dark]{ --ui-card: #2c2c2e; --ui-accent: #0a84ff; ... }
@theme inline    { --color-card: var(--ui-card); --color-accent: var(--ui-accent); ... }
```

Components then say `bg-card`, never `bg-zinc-900`. The names are what a value
is for — `card`, `sidebar`, `line`, `notice`, `danger` — because a name that
says `zinc-800` cannot be given a different value in the other theme.

| Token | Light | Dark |
| --- | --- | --- |
| `canvas` | `#f5f5f7` | `#1c1c1e` |
| `sidebar` | `#f4f4f6` | `#252527` |
| `tree` | `#fafafc` | `#1f1f21` |
| `toolbar` | `#fbfbfd` | `#2a2a2c` |
| `card` | `#ffffff` | `#2c2c2e` |
| `line` | `#e5e5ea` | `#3a3a3c` |
| `hairline` | `#f0f0f3` | `#3a3a3c` |
| `text` | `#1d1d1f` | `#f5f5f7` |
| `text-muted` | `#6e6e73` | `#98989d` |
| `text-faint` | `#a1a1a6` | `#6e6e73` |
| `control` / `control-line` | `#ffffff` / `#dcdce1` | `#1c1c1e` / `#48484a` |
| `select-fill` | `rgb(0 0 0 / .07)` | `rgb(140 140 150 / .26)` |
| `accent` | `#007aff` | `#0a84ff` |
| `notice` (bg / line / text) | `#fff6e5` / `#f5dfae` / `#7a5a10` | `rgb(255 159 10 / .13)` / `rgb(255 159 10 / .32)` / `#f0b429` |
| `danger` | `#d70015` | `#ff6961` |
| `live` | `#34794a` | `#5fd88a` |

`color-scheme` rides the same switch, so scrollbars, focus rings and native
form parts follow without being styled.

The two themes differ in those twenty values and in nothing else. No component
carries a `dark:` variant.

## Which theme

The OS decides by default. A select in the header, beside the language one,
overrides it, and the override is remembered.

It has three values, not two: System, Light, Dark. A two-state toggle can leave
the OS setting but never return to it, and "follow the OS" is the state most
people want to be in — it has to be reachable, not only initial. System is what
an installation starts in, and what a cleared preference falls back to.

That remembering costs one line elsewhere. `i18n/locale.ts` says the language
key is "the only thing this application writes to persistent browser storage",
and `e2e/bootstrap.spec.ts:152` holds it to that with an exact-match allowlist
rather than a count — deliberately, so a token written to storage fails the
suite. A theme key is a second preference and belongs there; the assertion is
updated to name both keys, and stays an allowlist.

## Components

`ui/form.tsx` keeps its exported class strings and its callers. Only the values
inside them change, from `zinc` literals to tokens. That is what lets the nine
panels importing it arrive at the new palette without being edited.

Added beside it, each one file:

- `Toolbar` — the section's title, the session line, and the controls at the right
- `Sidebar` — the primary navigation, in three groups, with icons
- `Card` and `Row` — an inset card of label-left / value-right rows
- `Notice` — the amber band, which `SavePreview`'s `NoticeList` renders into
- `Inspector` — the right pane and its toggle
- `Button` — primary, secondary, danger, replacing the three loose strings
- `icons.tsx` — one inline SVG sprite; no icon font, no network request

The ten components that style themselves move onto these: `App`,
`ui/CopyButton`, `ui/PasswordField`, `history/HistoryPanel`,
`connections/ConnectionTree`, `connections/ConnectionsPage`,
`connections/SavePreview`, `keys/RevealDialog`, `knownhosts/KnownHostsPanel`,
`remotekeys/RemoteKeyPanel`.

## Three groups in the sidebar

Ten sections listed flat give no clue which are near each other. They become:

- **Connections** — Connections, Config, Groups
- **Keys and hosts** — Keys, Known Hosts, Remote Keys
- **Maintenance** — Diagnostics, Secrets, Sync, History

The section identifiers stay English and untranslated for the reason `App.tsx`
already gives: they are the shell's routing vocabulary, and translating them
would make which panel is open depend on the display language. The group
headings are translated, because they are only headings.

Structurally this splits the one `<ul>` inside the existing `<nav>` into three,
each with an `aria-label` and a visible label hidden from the accessibility
tree. Every button keeps its role and its accessible name.

**The group labels are not headings.** `e2e/bootstrap.spec.ts:137` asks for the
level-2 heading named `鍵`, and Playwright matches accessible names by
substring unless told otherwise — a heading named `鍵とホスト` makes that query
match twice and fail on a strict-mode violation. A labelled list names the
group for a screen reader without putting anything new in the heading
namespace, which the panels own.

## The inspector

A configuration file's contents and this application's own notes are two
different things, and the host detail form currently mixes them: `HostName`
goes to `~/.ssh/config`, a colour goes to `metadata.json`. The inspector is
where the second kind goes, and it also holds this host's diagnostics and the
account of where an inherited value came from.

It is shut by default and opens from a button at the right of the toolbar. The
same button is in the same place on every screen, so "open the right pane" is
one gesture regardless of section. A section that has nothing to inspect does
not render the button at all, rather than disabling it.

**Two sections fill the inspector: Connections and Groups.** The other eight
render no toggle. The pane is something a section supplies rather than something
Connections owns, and Groups took it up for the same reason Connections did —
a group's colour, display order and hidden flag live only in `metadata.json`,
so they belong on the side that is not the file. The remaining eight are not a
backlog: a pane offered everywhere and empty in most places teaches people not
to open it.

*Written before the work as "Connections is the only section that fills the
inspector". Groups became the second when its screen was found to be carrying
seven controls per group, all expanded at once.*

**Its open state is the shell's, not a section's.** Opened on Connections, it is
still open on Keys. A pane that shut itself every time you changed section
would have to be reopened constantly, and the state is a preference about the
window, not about a host.

**The button carries an amber dot when what is inside it needs attention.**
Diagnostics moved into a pane that is shut by default would otherwise mean a
host with `duplicate_alias` looks identical to one without. The dot is what
makes the pane worth opening; without it, hiding diagnostics would be a
regression and the inspector would not be worth having.

The pane is an `<aside>` with a label, and the toggle carries `aria-expanded`
and `aria-controls`.

### No keyboard shortcut

macOS gives inspectors ⌥⌘I, and this application cannot have it. It is served
into whatever browser the user has set as default, and ⌥⌘I is the developer
tools in Chrome, Firefox and Safari alike — the browser takes the event first.
Every other ⌘-combination that reads as "inspector" is claimed by at least one
of those three.

So the toggle is a button and nothing else. The conflict-free space is
single-key shortcuts guarded on focus not being in a field, which is a web
convention rather than a macOS one; if that is wanted it is a separate
decision, made once for the whole application rather than for this pane.

## What does not change

The ten sections stay ten. Nothing is merged, split, renamed or removed. No
screen gains a capability. The connections tree keeps its grouping modes, its
drag and drop, and its filter. Every API call is the one it was.

The only motion is the inspector opening, and it is suppressed under
`prefers-reduced-motion`.

## Tests

The end-to-end suite selects by `getByRole` 128 times, `getByLabel` 54,
`getByText` 16, and the nine `locator()` calls address `body` or an
`aria-label`. **No test names a CSS class.** A change of appearance cannot
break it; only a change of role or accessible name can, and this design changes
neither.

What is new needs covering:

- the theme follows the OS, the override wins over it, and it survives a reload
- the storage allowlist holds exactly the two preference keys
- the inspector opens, stays open across a section change, and closes
- the dot appears when the selected host has diagnostics and not otherwise
- a section with nothing to inspect renders no toggle

`internal/ui/dist` is a committed bundle, so each step ends with `make build`;
the end-to-end job fails on a stale one.
