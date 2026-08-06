# Master password Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Widen the vault the master password already protects to hold named account passwords, named key passphrases and the object store's credentials, with the two kinds of secret in namespaces that cannot reference each other.

**Architecture:** `internal/secret` gains a version 2 document with two credential maps and three reference maps. The service exposes credentials by name and references by subject. `internal/remotesync` and `internal/keys` read what they need from it rather than from a form. No migration: version 1 is refused.

**Tech Stack:** Go 1.26.5, `golang.org/x/crypto` (already present), React 19.2.8, TypeScript 5.9.3, Vitest, Playwright. No new dependency.

## Global Constraints

- No new Go or npm dependency.
- `api/openapi.yaml` is the single source for `internal/api/models.gen.go` and `web/src/api/schema.d.ts`. Run `make generate`; `make verify-generated` must stay clean.
- Every user-visible string goes through `useTranslate`, in **both** locale blocks.
- `internal/ui/dist` is committed; run `make build` before the final commit.
- **A secret never leaves the process.** Not in a response body, a log line, a history entry, an error, or a path. Every response carries names and uses only. A test asserts this per route.
- A locked vault refuses every operation that would need the key, with `409` and a code the screen can act on.
- Nothing here changes what OpenSSH reads.

## File map

| File | Responsibility |
| --- | --- |
| `internal/secret/vault.go` | the version 2 document, sealing and opening |
| `internal/secret/service.go` | credentials, references, the unlocked key's lifetime |
| `internal/httpserver/password.go` | the routes over both |
| `internal/httpserver/sync.go` | settings read from the vault instead of the request |
| `internal/keys/service.go` | `Register` falls back to a stored passphrase |
| `web/src/diagnostics/PasswordPanel.tsx` | the credential manager |
| `web/src/sync/SyncPanel.tsx` | filled from the vault, locked state |
| `web/src/connections/HostDetail.tsx` | pick an account password for the alias |
| `web/src/keys/KeysScreen.tsx` | pick a passphrase for the key |

---

### Task 1: The version 2 document

**Files:**
- Modify: `internal/secret/vault.go`
- Test: `internal/secret/vault_test.go`

**Interfaces produced** — every later task consumes these:

```go
// Kind names a credential namespace. A host may reference only KindPassword and
// a key only KindKeyPassphrase: one namespace would let the host picker offer a
// key's passphrase, and picking it would send that passphrase to a remote host
// as a login password.
type Kind string

const (
	KindPassword      Kind = "password"
	KindKeyPassphrase Kind = "key_passphrase"
)

type SyncSettings struct {
	Endpoint, Bucket, Region, AccessKeyID, SecretAccessKey, Direction string
}

func (v *Vault) Names(kind Kind) []string
func (v *Vault) Set(kind Kind, name, secret string) error
func (v *Vault) Delete(kind Kind, name string) error
func (v *Vault) Secret(kind Kind, name string) (string, bool)
func (v *Vault) Assign(kind Kind, subject, name string) error   // alias or key path
func (v *Vault) Unassign(kind Kind, subject string)
func (v *Vault) Assigned(kind Kind, subject string) (string, bool)
func (v *Vault) Uses(kind Kind, name string) []string
func (v *Vault) Sync() SyncSettings
func (v *Vault) SetSync(SyncSettings)
```

`Assign` refuses a name that does not exist in that kind, and `Delete` refuses a
name with uses, returning them.

- [ ] **Step 1: Write the failing tests**

```go
func TestVaultKeepsTheTwoNamespacesApart(t *testing.T) {
	vault, err := secret.NewVault([]byte("a master password"))
	if err != nil { t.Fatal(err) }
	if err := vault.Set(secret.KindPassword, "office", "s3cret"); err != nil { t.Fatal(err) }
	if err := vault.Set(secret.KindKeyPassphrase, "build", "phrase"); err != nil { t.Fatal(err) }

	// A host cannot reference a key's passphrase. This is the separation as a
	// test rather than as a comment: one namespace would make it expressible,
	// and picking it would send a key passphrase to a remote host.
	if err := vault.Assign(secret.KindPassword, "web-1", "build"); err == nil {
		t.Error("a host referenced a key passphrase")
	}
	if err := vault.Assign(secret.KindKeyPassphrase, "keys/id_work", "office"); err == nil {
		t.Error("a key referenced an account password")
	}
	if err := vault.Assign(secret.KindPassword, "web-1", "office"); err != nil {
		t.Errorf("a host could not reference an account password: %v", err)
	}
}

func TestVaultRefusesToDeleteACredentialInUse(t *testing.T) { /* Uses() reported in the error */ }

func TestSealedBytesCarryNeitherNameNorSecretNorSubject(t *testing.T) {
	// The existing v1 test asserts this; extend it to the new fields, including
	// the object store's access key.
}

func TestAVersionOneDocumentIsRefused(t *testing.T) {
	// Opening `{"passwords":{"web-1":"s3cret"}}` answers secret.ErrOldVault, and
	// the message says to set the passwords again. There is at most one such
	// document in the world; a migration would be larger than what it migrates.
}
```

- [ ] **Step 2: Run them and watch them fail**

```
go test ./internal/secret/
```

- [ ] **Step 3: Implement the document**

The sealed JSON is the shape in the spec: `version`, `passwords`,
`keyPassphrases`, `hosts`, `keys`, `sync`. Keep the existing envelope, KDF and
bounded cost exactly as they are — only the plaintext inside changes.

- [ ] **Step 4: Run the tests, then the package**

```
go test ./internal/secret/
```

- [ ] **Step 5: Commit**

```bash
git commit -m "Give the vault two namespaces and names"
```

---

### Task 2: The service, and the routes over it

**Files:**
- Modify: `internal/secret/service.go`, `internal/httpserver/password.go`, `api/openapi.yaml`
- Test: `internal/secret/service_test.go`, `internal/httpserver/password_test.go`

**Routes.** Existing `/api/v1/passwords/*` keeps initialise, unlock, lock and
status. Added:

| Method | Path | Body | Answer |
| --- | --- | --- | --- |
| `GET` | `/api/v1/credentials` | — | both lists: name, kind, uses |
| `PUT` | `/api/v1/credentials/{kind}/{name}` | `{secret}` | the lists |
| `DELETE` | `/api/v1/credentials/{kind}/{name}` | — | the lists, or `409 credential_in_use` with its uses |
| `PUT` | `/api/v1/credentials/{kind}/assign` | `{subject, name}` | the lists |
| `DELETE` | `/api/v1/credentials/{kind}/assign/{subject}` | — | the lists |

`{kind}` is `password` or `key_passphrase`; anything else is `400`.

- [ ] **Step 1: Write the failing handler tests**

One per row above, plus: every one answers `409 vault_locked` with the vault
shut, and **no response body contains the secret** — assert on the whole body,
not on a field.

- [ ] **Step 2: Run and watch fail**
- [ ] **Step 3: Implement the service methods and the handlers**
- [ ] **Step 4: `make generate`, run the tests, `make verify-generated`**
- [ ] **Step 5: Commit** — `git commit -m "Serve credentials by name"`

---

### Task 3: The object store reads its credentials from the vault

**Files:**
- Modify: `internal/httpserver/sync.go`, `api/openapi.yaml`
- Test: `internal/httpserver/sync_test.go`

`PUT /api/v1/sync/settings` writes into the vault instead of into memory, and
refuses with `409 vault_locked` when it is shut. `GET /api/v1/sync` answers with
the endpoint, the bucket, the region and the direction — **never the access key
or the secret** — plus `locked`, so the screen can say why the form is empty.

Push and pull take their credentials from the vault.

- [ ] Steps 1–5 as above. The test that matters: `GET /api/v1/sync` never
      carries the access key, asserted on the whole body.

---

### Task 4: A key with a stored passphrase registers in one action

**Files:**
- Modify: `internal/keys/service.go`, `internal/httpserver/keys.go`
- Test: `internal/keys/service_test.go`

`Register` takes an empty passphrase and, when the vault holds one for that key's
relative path, uses it. When it does not, the behaviour is exactly as today.

The lookup is injected — `internal/keys` must not import `internal/secret`, the
same way it does not import the configuration engine to ask what a group is.

- [ ] Steps 1–5 as above.

---

### Task 5: The screens

**Files:** `PasswordPanel.tsx`, `SyncPanel.tsx`, `HostDetail.tsx`, `KeysScreen.tsx`, `messages.ts`

- The panel becomes the credential manager, the two kinds listed apart.
- Host detail picks from account passwords only; keys pick from key passphrases
  only. **The picker for one kind never lists the other**, which is the
  separation made visible.
- Sync says it is locked and offers to unlock in place.

- [ ] Steps 1–5 as above, per screen, with the vitest for each.

---

### Task 6: End to end, the README, and the bundle

- [ ] The end-to-end case from the spec: set a master password, store one
      credential, point two aliases at it, and read the sealed file to confirm
      it carries neither alias nor secret.
- [ ] Rewrite the README's passphrase boundary rather than leave it false, and
      record the trade the spec states.
- [ ] `make build`, the whole gate, and the dependency check.

---

## Self-review

**Spec coverage.** The two namespaces are Task 1 and are enforced again in the
pickers in Task 5. The object store is Task 3, key passphrases Task 4, the
screens Task 5, the README Task 6. The unlock timing — nothing asked at startup,
each screen offering it — is Task 5's shape and Task 3's `locked` field.

**Not covered, deliberately.** No migration, no recovery, no command-line
unlock: each is a spec decision with its reason recorded there.

**Type consistency.** `Kind`, `KindPassword` and `KindKeyPassphrase` are defined
in Task 1 and used in every later task, including as the `{kind}` path segment.
`SyncSettings` is defined in Task 1 and consumed in Task 3.
