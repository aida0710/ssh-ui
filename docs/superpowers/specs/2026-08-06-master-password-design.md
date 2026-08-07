# One master password, and secrets with names

The vault already has a master password: a passphrase this application never
stores, from which Argon2id derives the key that seals
`~/.ssh/sshc/secrets`. What it protects is one map — a remote account's
password, keyed by alias.

Three things sit outside it that belong inside, and the map has the wrong shape.

## The shape

A secret is a **credential**: a name and a value. Everything else references one
by name, so a password used by twenty machines is stored once and rotated once —
which is the whole reason for the change.

There are two credential namespaces, and they do not mix.

```json
{
  "version": 2,
  "passwords":      { "office-vm": "…" },
  "hosts":          { "web-1": "office-vm", "web-2": "office-vm" },
  "keyPassphrases": { "build-key": "…" },
  "keys":           { "keys/work/id_work": "build-key" },
}
```

The object store's settings are **not** in it. They live beside it, in
`sshc/sync-settings`, sealed with the same master password:

```json
{ "endpoint": "…", "bucket": "…", "region": "…",
  "accessKeyId": "…", "secretAccessKey": "…", "direction": "…" }
```

An account password and a key passphrase are kept apart, and not for tidiness.
One namespace would mean the host's password picker offers key passphrases as
candidates: pick the wrong entry and this application sends a private key's
passphrase to a remote host as a login password. Two namespaces make that
impossible to express rather than merely unlikely — a host references
`passwords` and a key references `keyPassphrases`, in the format, in the API and
in the types.

They differ in what they protect, too. An account password admits you to one
account; a key passphrase unlocks a key that may admit you to many machines.
Sharing is normal within each and meaningless across them.

`hosts` keyed by alias is what exists today, except that the value is a name
rather than the secret itself. `keys` maps a key's workspace-relative path the
same way, because one passphrase across several keys is ordinary.

There is no migration. The vault format is version 2 and a version 1 document is
refused with a message saying to set the passwords again — there is one such
document in the world at most, and inventing a migration for it would be more
code than the thing it migrates.

## What the master password now covers

**Remote account passwords.** As today, through `SSH_ASKPASS`, but resolved
through a credential name.

**Object store credentials.** They are supplied per run today and written
nowhere, so every push means typing an access key again. They are now stored —
in their own sealed file rather than in the vault.

The distinction matters and the code already argued for it before this design
did. `SyncHandlers.Configure` carried the reason:

> A snapshot that carried the key to its own bucket would be a bootstrapping
> convenience and a much larger blast radius, and it would mean anybody who
> obtained one snapshot could fetch every later one.

The vault travels: `Collect` names `sshc/secrets` outright. Putting the access
key inside it would put the key to the bucket inside the bucket. Someone who
obtained one snapshot by any means — a backup, a stray copy — and its passphrase
would gain the live bucket and every future snapshot, rather than the one
snapshot they already had.

So the settings live in `sshc/sync-settings`, sealed with the same master
password and never collected. `Collect` lists what it takes, so a new file under
`sshc/` is excluded by construction rather than by a rule someone has to
remember.

The bootstrap follows from that and is stated rather than solved: a machine that
has never synced types its credentials once. That is one entry per machine, not
per run, and it is the price of the key to the bucket not being in the bucket.

**Private key passphrases.** This changes a boundary the README states:

> パスフレーズはアプリケーションでは一切保存しません。保持は利用者の明示的な
> 操作による macOS Keychain または ssh-agent への委譲のみです。

The boundary existed because storing a passphrase would make this application a
second, weaker ssh-agent. It does not become one. `Register` already takes a
passphrase and hands it to `ssh-add` on standard input; storing it means
remembering the value that form already receives. The application stays the
thing that *unlocks* the agent rather than a thing that answers for it, and a
key with a stored passphrase is added to the agent in one action instead of two.

What genuinely changes:

- On a stolen machine, an encrypted private key is protected by the master
  password rather than by its own passphrase. For anyone already delegating to
  the login Keychain this is a move rather than a new exposure — the passphrase
  was already on disk — but the lifetimes differ: the Keychain closes when the
  Mac locks, and the vault stays open for the session.
- One password now opens every key. That is the trade, taken deliberately.

The README's boundary is rewritten rather than quietly broken.

## What stays outside

**The display language.** It is not a secret, and behind the lock the unlock
screen itself could not be shown in the user's language. It stays in
`localStorage`.

**`metadata.json`.** Colours, groups, favourites and notes are not secrets, and
locking them would mean the configuration cannot be read or edited until the
vault is open. The application stays usable without ever unlocking; the lock is
needed to *use* a secret, not to see the configuration.

## The screens

**Password vault** becomes **Master password**, and its panel manages both
namespaces, listed apart and labelled for what they are. A credential names what
uses it, and deleting one in use is refused rather than left to break a
connection later.

**Host detail** picks an account password for the alias from a list instead of
typing one into a field. The list holds account passwords only. Typing a new one
is still offered, and creates a credential named after the alias.

**Keys** does the same for a key's passphrase, from the key-passphrase list
only, and the agent registration uses the stored one when there is one.

**Remote sync** reads its settings from the vault and writes them back, so the
form is filled in on the second run.

## When the vault is opened

There is one route by which a master password is entered: the screen. The
binary's other invocation — `sshc <prompt>`, the askpass helper OpenSSH execs
— holds no secret and can decrypt nothing; it asks the running, unlocked process
over loopback with a one-time token. It is not a second way in.

Nothing is asked at startup. The screens that need a secret say they are locked
and offer to open it there: Remote sync, whose settings now live inside, and
Keys, when a stored passphrase would be used. Reading and editing the
configuration never asks, because the lock is for using a secret rather than for
seeing the configuration.

There is no command-line option for the master password, and there will not be
one that takes it as an argument: argv is readable by every process on the
machine, and this repository already refuses to put a passphrase there for key
generation. If unattended start is ever wanted, the shape is standard input fed
from somewhere that protects it —

```
security find-generic-password -w -s sshc | sshc -unlock-stdin
```

— and it is not built now, because a guess at an unattended workflow nobody has
run yet is usually the wrong shape.

## Losing the master password

It cannot be recovered, and nothing here pretends otherwise: the key exists only
while the process holds it, derived from a passphrase that is stored nowhere.
Losing it loses the object store credentials, every account password and every
key passphrase.

What it does not lose is anything OpenSSH reads. The configuration, the groups
and the private keys themselves are untouched by the vault; a forgotten master
password costs the secrets and not the workspace. The panel offers to discard
the vault and start again, because the alternative is telling the user to delete
a file by hand.

## Boundaries

- The vault is still one sealed file, still AES-256-GCM with an Argon2id key,
  still with the envelope's bounded cost so a hostile header cannot cost ninety
  minutes of a core.
- A secret still never appears in a response, a log line, a history entry or an
  error. The panel lists names and what uses them.
- Locking the vault still forgets the key. Nothing derived from it is cached
  past a lock.
- Nothing here changes what OpenSSH reads.

## Testing

- `internal/secret`: the version 2 round trip; a version 1 document refused;
  neither a credential name nor a secret nor an alias appearing in the sealed
  bytes; deleting a credential in use refused with what uses it; a host refusing
  to reference a key passphrase and a key refusing to reference an account
  password, which is the separation stated as a test rather than as a comment.
- `internal/httpserver`: every new route refuses a locked vault; a secret never
  appears in any response; the credential list carries names and uses only.
- `internal/keys`: `Register` uses a stored passphrase when one exists and asks
  when none does.
- `internal/remotesync`: settings read from the vault reach the client.
- Web: the credential picker on the host detail and the keys screen; the sync
  form filled from the vault; deleting a used credential refused in the panel.
- End to end: set a master password, store a credential, point two aliases at
  it, and confirm the sealed file carries neither alias nor secret.
