# The master password becomes the way in

## What this changes

The master password was a per-feature unlock. Nothing was asked at startup, and
each screen asked for itself when it needed a secret. That was a deliberate
choice made earlier in the same day this document replaces it, and the reason it
is being replaced is worth writing down rather than quietly reversing.

Generational backups are to be sealed. A sealed backup needs a key, the key
comes from the master password, and so every write that keeps a backup needs the
vault to be open. Lazy unlocking makes that a question with no good answer:
either a backup taken while the vault is shut is written in the clear, which
defeats sealing it, or it is skipped, which makes whether a change can be undone
depend on a state the user is not thinking about.

Requiring the master password to use the application at all removes the
question. The vault is open whenever anything can be written, so a backup can
always be sealed, and there is one rule instead of three cases.

## The gate

- **First run.** Setting a master password is part of the initial setup. No other
  screen is reachable until it is set. It cannot be recovered; that is stated
  where it is set, not afterwards.
- **Later runs.** The first screen asks for it. Until it is given, every
  `/api/v1` route refuses with `vault_locked`, except:
  - `POST /api/v1/session/renew` — the session must be able to survive a reload
    before there is anything to unlock.
  - `GET /api/v1/passwords`, `POST /api/v1/passwords/initialise`,
    `POST /api/v1/passwords/unlock` — the gate itself.
  - `GET /api/v1/health`.
- **Idle.** The existing eight-hour idle lock stays and now locks the
  application, not merely the vault. A machine left overnight asks again.
- **The askpass helper** is unchanged: it redeems a token against an open vault
  and already fails when the vault is shut.

### What the gate is not

It does not encrypt `~/.ssh`. The configuration and the private keys stay where
OpenSSH reads them, in the clear, because otherwise `ssh` would not work. What
the gate protects is this application's interface, the vault, and — once they
are sealed — the generational backups. Somebody holding the disk still holds the
keys. Saying this plainly matters more than the feature does: a lock that is
believed to do more than it does is worse than no lock.

## Sealed backups

`storage.Manager` takes an injected sealer, so the storage layer never imports
the secret package — the same reasoning that keeps `keys` from importing it to
ask where a passphrase lives. Every backup written under
`~/.ssh/ssh-ui/backups/` is ciphertext. Rollback and history restore open them
with the same key, which the gate guarantees is there.

Because the gate makes the vault open whenever a write is possible, there is no
unsealed case. A manager built without a sealer is a programming error, not a
runtime state, and it fails loudly rather than writing plaintext.

## The backups that were being skipped

`SkipBackup` exists because a copy of the previous contents may be key material.
Sealing removes that reason. It comes off:

- the vault write (`ssh-ui/secrets`),
- the sync settings write (`ssh-ui/sync-settings`),
- the key passphrase change,
- the private keys a pull applies from a snapshot.

It stays on the sync state file, which names no secret and changes on every
sync: a generation of it per sync is noise, not history.

This is where it buys the most. A passphrase change that goes wrong is
unrecoverable today — `Rollback` refuses and says so — and a pull that
overwrites a local key is exactly the case where the previous key is what you
want back.

The backups do not travel: `remotesync.Collect` walks `~/.ssh/keys` and names
the files it takes, and `ssh-ui/backups` is not among them.

## The bucket

- **A path, defaulting to the root.** The objects are pinned under `ssh-ui/`
  inside a bucket the user already named for this application. The path becomes
  a setting, empty by default, stored sealed with the rest.
- **An honest name.** `workspace.snapshot` says nothing: inside the envelope it
  is a tar.gz, and the object itself is ciphertext. It becomes
  `workspace.tar.gz.enc`. An existing snapshot under the old key is orphaned;
  one push replaces it, and the old object can be deleted by hand.
- **A dated copy of every push**, at `snapshots/YYYY-MM-DD-HHMMSS.tar.gz.enc`,
  written before the live object so that a failure to write it fails the push
  and leaves nothing half-done.

The live object keeps its fixed key. That is not cosmetic: the conditional write
— `If-None-Match: *` for the first push and `If-Match: <the ETag we last saw>`
for every one after — is what makes it impossible to silently clobber another
machine's work, and it needs one object to condition on. Dated names instead of
a fixed one would remove it.

The cost of the copies is stated rather than designed around: every push leaves
another complete ciphertext copy of everything in `~/.ssh`, and an old copy holds
keys that have since been rotated or deleted. The blast radius of leaked bucket
credentials therefore stops shrinking over time. A bucket lifecycle rule
expiring `snapshots/` is what bounds it, and that belongs to the bucket rather
than to this application.

## Testing

- The gate is a middleware, so the route table test that already sweeps `/api/`
  is the place that proves no route was forgotten: every route not on the
  exemption list must answer `vault_locked` while shut.
- The end-to-end fixture sets a master password once, since every screen is now
  behind it.
- Sealing is proved by reading a backup off the disk and finding neither the
  previous contents nor a recognisable header in it, the same shape as the test
  that proves the vault file is ciphertext.
- Removing `SkipBackup` is proved by rolling back each of those writes, which is
  the thing that cannot be done today.
