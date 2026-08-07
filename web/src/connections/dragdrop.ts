// What a drag is carrying, and which drops are worth offering.
//
// Every rule here mirrors a refusal the server already makes. They exist so a
// target that cannot work is not offered — not to enforce anything. Every drop
// still goes through the API, and a refusal that arrives is still shown.

export type DragPayload =
  | { kind: "connection"; path: string; alias: string; group: string }
  | { kind: "group"; name: string };

// A private type on dataTransfer, so a drag that began outside this page is not
// mistaken for one of these. It is only ever read from `types`: a dragover
// handler may not read the data itself, which is protected until the drop.
export const dragMimeType = "application/x-sshc-drag";

// MaxGroupSegments in internal/application/grouppath.go. The limit comes from
// the key scanner, not from anything here: it walks eight directories down from
// ~/.ssh and "keys" spends one, so a key inside a seventh group segment would be
// reported as depth_exceeded and vanish from the inventory.
const maxGroupSegments = 6;

// The empty string is the "no group" target: the entry file for a connection,
// the top level for a group.
const noGroup = "";

function segments(name: string): number {
  return name === noGroup ? 0 : name.split("/").length;
}

function basename(name: string): string {
  const index = name.lastIndexOf("/");
  return index < 0 ? name : name.slice(index + 1);
}

function isSelfOrDescendant(name: string, candidate: string): boolean {
  return candidate === name || candidate.startsWith(`${name}/`);
}

export function canDrop(payload: DragPayload, target: string, groups: string[]): boolean {
  // A connection has one place it lives, so the only drop with nothing to do is
  // the one onto where it already is.
  if (payload.kind === "connection") {
    return payload.group !== target;
  }
  // A group cannot be put inside itself, at any depth.
  if (isSelfOrDescendant(payload.name, target)) return false;
  const moved = target === noGroup ? basename(payload.name) : `${target}/${basename(payload.name)}`;
  if (moved === payload.name) return false;
  if (groups.includes(moved)) return false;
  return segments(moved) <= maxGroupSegments;
}
