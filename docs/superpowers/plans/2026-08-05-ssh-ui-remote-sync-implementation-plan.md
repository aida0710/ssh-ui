# SSH UI Remote Sync Implementation Plan

**Status:** design, not yet implemented.

**Goal:** Keep one `~/.ssh` in step across several machines through a Cloudflare R2 bucket. The whole workspace travels — the entry file, every file the Include graph reaches, `ssh-ui/metadata.json`, and **the private keys** — as one encrypted snapshot. A push never overwrites a snapshot it has not seen. A pull is an ordinary journalled transaction, so it is previewed, backed up and rollable-back exactly like every other write this application makes.

**Architecture:** Two new packages. `internal/objectstore` is an S3-compatible client: SigV4 signing, `GET`/`PUT`/`HEAD`, conditional writes, nothing else. `internal/sync` owns the snapshot format, the encryption, the conflict rule and the translation of a pull into a `storage.Request`. Neither knows what an `ssh_config` is. `internal/application` gains the use case that ties a successful commit to a queued push. Credentials and the encryption passphrase live in `internal/secret` — the Keychain package the password-authentication plan introduces, which is why **that plan lands first**.

**Tech Stack:** Go 1.26.5. SigV4 needs `crypto/hmac`, `crypto/sha256`, `encoding/hex`, `net/http`, `time` — standard library. The snapshot needs `archive/tar` and `compress/gzip` — standard library. The encryption needs `crypto/aes`, `crypto/cipher`, `crypto/rand` — standard library — and one key-derivation function, discussed below. React 19.2.8, TypeScript 5.9.3, Vitest 4.1.1, Playwright 1.62.1.

## 1. Why one object and not one object per file

The obvious design is a file per object: it gives per-file conflict detection for free and matches the per-file digests the storage layer already computes.

It is the wrong design here, for one reason. **A configuration is only meaningful as a set.** `~/.ssh/config` says `Include connections/work/*.conf`; `metadata.json` names groups that must have directories; `IdentityFile` lines name key files. Uploading files independently produces, between the first and last request, a remote state that never existed on any machine — an Include reaching a file that is not there yet, a group declared with no directory. A machine that pulls in that window gets a configuration that is not merely stale but incoherent.

So: **one object, one snapshot, one atomic `PUT`.** R2 completes or does not complete a `PUT`; there is no half-written object. The set arrives whole or not at all.

The cost is that a one-byte change re-uploads everything. For a `~/.ssh` this is kilobytes; the trade is not close.

### The snapshot format

```
snapshot := nonce || AES-256-GCM(key, nonce, gzip(tar(manifest.json, files…)))
```

`manifest.json` is the first tar entry and carries:

```json
{
  "schemaVersion": 1,
  "createdAt": "2026-08-05T10:00:00Z",
  "origin": "an opaque per-installation id, not a hostname",
  "files": [
    { "path": "config", "sha256": "…", "mode": "0600" },
    { "path": "connections/work/lon.conf", "sha256": "…", "mode": "0600" },
    { "path": "keys/work/id_ed25519", "sha256": "…", "mode": "0600", "secret": true }
  ]
}
```

- **Paths are workspace-relative and forward-slashed**, the same vocabulary `storage.Workspace` already uses. A path that does not resolve inside the workspace is refused on read — a snapshot is untrusted input, and `../` in a tar is the oldest trick there is.
- **`mode` travels** because a private key with the wrong bits is a private key OpenSSH refuses. Only `0600` and `0700` are accepted; anything else is refused rather than normalised, so a snapshot cannot widen permissions.
- **`origin` is not a hostname.** It exists so the UI can say "this snapshot came from a different installation", and a hostname in an object anyone with the bucket can read is an unnecessary disclosure.
- **`secret: true`** marks a private key so the pull can apply it with `storage.Change{SkipBackup: true}`. That field exists in the storage layer for exactly this reason, and its comment already says why: *the previous contents may be a private key, and the design refuses to leave a second copy of key material in `~/.ssh/ssh-ui/backups/`.* A pull that ignored it would defeat that decision from a new direction.

## 2. Encryption is not optional

Private keys are in the snapshot. That decision was taken deliberately; it makes the encryption a load-bearing part of the design rather than a nicety.

- **AEAD:** AES-256-GCM. Standard library. The 12-byte nonce is `crypto/rand` per snapshot and is prefixed to the ciphertext. The manifest is inside the ciphertext, so an observer learns the object's size and nothing else — not the number of files, not their names, not how many keys there are.
- **Key derivation:** **Argon2id**, `golang.org/x/crypto/argon2`. The threat is an offline attack on an object that anyone who obtains the bucket credentials can download and keep. PBKDF2 — available as stdlib `crypto/pbkdf2` since Go 1.24 — is materially weaker against a GPU for the same wall-clock cost, and this is precisely the case where that difference is the whole security argument.

  **The honest cost:** `golang.org/x/crypto` is already a direct dependency (`go.mod` line 9) and `golang.org/x/sys` is already listed as indirect, so **`go.mod` and `go.sum` do not change**. But today `x/sys` reaches the tree only through the code-generation tool; `argon2` imports `blake2b` which imports `x/sys/cpu`, so this links it into the shipped binary for the first time. That is not a new dependency but it is a new thing in the artefact, and the release plan's `otool -L` check and dependency review should be told. If that is judged unacceptable, `crypto/pbkdf2` with a high iteration count is the fallback and the change is four lines.
- **Parameters travel in the clear**, as a small header before the nonce: KDF id, salt, time, memory, parallelism. A future machine with a different build must be able to derive the same key; hard-coding them would make a parameter change an unreadable-archive event.
- **The passphrase is not stored by default.** Storing it beside the R2 credentials would make one Keychain a single point of total compromise: bucket plus passphrase is every private key. Storing it is offered, opt-in, with that sentence on screen.

## 3. The conflict rule

This application's one real guarantee is that it never writes over a file it has not read. Sync must inherit that or it dissolves it.

**The remote's ETag is the generation.** Local state, in `~/.ssh/ssh-ui/sync-state.json`, records the ETag of the snapshot this machine last pushed or pulled, and the manifest it contained.

- **First push:** `PUT` with `If-None-Match: *`. Succeeds only if no object exists. A `412` means another machine got there first.
- **Later push:** `PUT` with `If-Match: <last known ETag>`. A `412` means the remote moved since we last saw it.
- **Pull:** `GET`, and record the returned ETag.

This is a compare-and-swap, so **no push can silently clobber another machine's work**, which is the property that makes the word "auto" safe to use.

> **To verify before implementing:** R2's support for `If-Match`/`If-None-Match` on `PutObject` must be confirmed against the current Cloudflare API documentation and against a live bucket. If conditional `PUT` is unavailable, the fallback is a read-modify-write with the ETag re-checked by a `HEAD` immediately before the `PUT` — a narrower race, not an eliminated one — and the UI must then say that two machines pushing within the same second can lose one side's change. This plan does not pretend to have tested that; it is Task 2's first job.

### What happens on a 412

Nothing is written and nothing is lost. The user is shown a three-way comparison, per file, between:

1. the snapshot this machine last synced (the base — its manifest is in `sync-state.json`, its bytes are re-fetchable by ETag or reconstructible from the local backup generation),
2. what is on this disk now,
3. what the remote holds now.

That is the same shape as `storage.ConflictError`, which already carries `Path`, `Expected` and `Actual` and is already rendered by `SavePreviewPanel`. The sync conflict view is the existing view over a different pair of inputs — **no new conflict UI, no second mental model**.

Resolution is explicit: take mine, take theirs, or open the file in the Config Explorer and merge by hand. There is no automatic merge. A merge of two `ssh_config` files that both changed the same `Host` block has no correct answer, and guessing one would violate the byte-preservation promise the parser exists to keep.

## 4. A pull is a transaction

This is the part that costs the least and buys the most.

A pull decrypts the snapshot, compares each manifest entry's digest with the file on disk, and assembles **one `storage.Request`**:

```go
storage.Request{
    Operation: "sync.pull",
    Changes: []storage.Change{
        {Path: "config", Contents: …, Precondition: storage.Precondition{Exists: true, Digest: localDigest}},
        {Path: "keys/work/id_ed25519", Contents: …, Precondition: …, SkipBackup: true},
    },
    Removals: …, // files the snapshot does not have and the last sync did
}
```

Everything then follows for free:

- the `Manager.Validate` hook re-parses and re-resolves the configuration, so a snapshot that would break the Include graph is **refused before a byte lands**;
- every replaced file except the keys is backed up into a generation directory, so a bad pull is one click of the existing History screen away from being undone;
- the journal makes an interrupted pull completable;
- the preview the user approves is the existing per-file diff.

A pull that could not be expressed as a `storage.Request` would be a pull that escapes every safety property this codebase has. That it *can* be is the strongest argument that this design fits the program it is being added to.

**Removals need care.** A file present locally and absent from the snapshot is either "deleted on the other machine" or "created here since the last sync". The last-synced manifest distinguishes them: present in the base and absent from the remote means deleted; absent from both means new here and left alone.

## 5. What "auto" means

`Manager.Commit` returning successfully is the trigger. It is the only moment at which the workspace is known to be consistent, and it is already the single funnel every write passes through.

- The push is **queued, debounced (5 s) and asynchronous**. No HTTP response waits for R2. A localhost UI that stalls because a bucket is slow would be a worse product than one that does not sync.
- **Failure is surfaced, not retried forever.** A `412` becomes a conflict notice in the UI. A network error retries three times with backoff and then becomes a notice with a manual retry. A sync that quietly stops working is indistinguishable from one that works.
- **`sync-state.json` is written through the same `storage.Manager`**, so the record of what was synced is itself journalled and cannot be left half-written.
- Automatic *pull* is not part of this. Pulling changes files under the user; it happens when asked, or on an explicit "check for changes" the UI offers on load.

## Out of Scope

- S3 providers other than R2. The signer is generic SigV4 and will very likely work against S3 and Backblaze B2, but only R2 is tested and only R2 is offered.
- Multipart upload. A `~/.ssh` that exceeds the 5 GB single-`PUT` limit is not a case this serves.
- Server-side versioning, lifecycle rules, or restoring an older snapshot from the bucket. Local history already keeps generations, and that is the restore story.
- Syncing while the application is not running.
- Sharing a bucket between two people. The conflict rule is correct for it, but the interface is written for one person's machines.
- `known_hosts`. It is per-machine, it is large, and merging it is a different problem. A later plan may take it.

## File Structure

```
internal/objectstore/sigv4.go            # new: canonical request, string to sign, signature
internal/objectstore/sigv4_test.go       # new: AWS published test vectors
internal/objectstore/client.go           # new: Get, Put, Head, conditional headers
internal/objectstore/client_test.go      # new: httptest.Server, no network
internal/sync/snapshot.go                # new: manifest, tar, gzip
internal/sync/snapshot_test.go           # new: round trip, traversal refusal, mode refusal
internal/sync/crypto.go                  # new: header, KDF, AES-GCM
internal/sync/crypto_test.go             # new
internal/sync/plan.go                    # new: snapshot + local state → storage.Request
internal/sync/plan_test.go               # new
internal/sync/service.go                 # new: push, pull, conflict, sync-state.json
internal/sync/service_test.go            # new
internal/application/syncqueue.go        # new: the post-commit hook, debounced
internal/httpserver/sync.go              # new: status, push, pull, resolve, settings
api/openapi.yaml                         # + SyncStatus, SyncConflict, five operations
web/src/sync/SyncPanel.tsx               # new
web/src/i18n/messages.ts                 # + en and ja
web/e2e/sync.spec.ts                     # new, against a local fake object store
```

## Task 1: SigV4, against the published vectors

**Files:** create `internal/objectstore/sigv4.go`, `internal/objectstore/sigv4_test.go`.

**Interfaces:**

```go
type Credentials struct{ AccessKeyID, SecretAccessKey string }

// Sign adds Authorization, X-Amz-Date and X-Amz-Content-Sha256 to req.
// payload is the exact body; a nil payload signs the empty-string hash.
func Sign(req *http.Request, credentials Credentials, region, service string,
    payload []byte, now time.Time) error
```

**What it must not change:** nothing; new package.

**Tests.** AWS publishes signature test vectors (`aws-sig-v4-test-suite`) with the expected canonical request, string-to-sign and signature for each. Transcribe four of them — including one with query parameters and one with a body — and assert all three intermediate strings, not only the final signature. A signer tested only on its output tells you nothing about *why* it is wrong when it is.
- `TestCanonicalRequestMatchesThePublishedVector`
- `TestStringToSignMatchesThePublishedVector`
- `TestSignatureMatchesThePublishedVector`
- `TestUnsignedPayloadIsRefused` — this client always signs the payload; `UNSIGNED-PAYLOAD` is not a mode it offers.
- `TestSignIsDeterministicForAFixedClock` — `now` is a parameter, never `time.Now()` inside, so every test is exact.

**Verification:** `go test ./internal/objectstore -run TestSig -v`.

## Task 2: The object client, and the conditional-write question

**Files:** create `internal/objectstore/client.go`, `internal/objectstore/client_test.go`.

**Interfaces:**

```go
type Client struct {
    HTTP     *http.Client
    Endpoint string // https://<account>.r2.cloudflarestorage.com
    Bucket   string
    Region   string // "auto" for R2
    Creds    Credentials
    Now      func() time.Time
}

type Object struct { Body []byte; ETag string }

func (c Client) Get(ctx context.Context, key string) (Object, error)
func (c Client) Head(ctx context.Context, key string) (string, error) // ETag
// Put writes the object. ifMatch and ifNoneMatch are mutually exclusive; both
// empty is an unconditional write, which this package's callers never use.
func (c Client) Put(ctx context.Context, key string, body []byte, ifMatch, ifNoneMatch string) (string, error)

var ErrPreconditionFailed = errors.New("the object changed since it was last read")
var ErrNotFound = errors.New("no object under that key")
```

**The first job of this task is not code.** Confirm against Cloudflare's current R2 documentation, and then against a live bucket, that `PutObject` honours `If-Match` and `If-None-Match` and returns `412`. Record the answer in this file before writing `service.go`, because section 3's guarantee depends on it and the fallback changes what the UI must say.

**Tests.** `httptest.Server` only; no test in this package reaches the network.
- `TestPutSendsIfMatchWhenGiven` and `TestPutSendsIfNoneMatchWhenGiven`, and that supplying both is a programming error caught before the request.
- `TestPutMaps412ToErrPreconditionFailed`, `TestGetMaps404ToErrNotFound`.
- `TestEveryRequestIsSigned` — the handler asserts an `Authorization` header of the right shape on every method.
- `TestNoRequestCarriesCredentialsInTheURL`.
- `TestBodyIsNeverLogged` — the package has no logger.

**Verification:** `go test ./internal/objectstore -v`.

## Task 3: The snapshot

**Files:** create `internal/sync/snapshot.go`, `internal/sync/snapshot_test.go`.

**Interfaces:**

```go
func Build(workspace *storage.Workspace, graph *config.Graph, inventory *keys.Inventory) ([]byte, Manifest, error)
func Read(archive []byte) (Manifest, map[string][]byte, error)
```

**What it must not change:** nothing on disk. `Build` reads.

**Tests.**
- `TestBuildIncludesEveryFileTheGraphReachesAndEveryKey` — a fixture with a nested group, two included files and two keys; the manifest lists exactly them, and `metadata.json`.
- `TestBuildExcludesFilesOutsideTheWorkspace` — an `Include /etc/ssh/ssh_config` is in the graph and must not be in the snapshot. This application never writes outside `~/.ssh` and must never carry a file it would refuse to write.
- `TestReadRefusesAPathThatEscapesTheWorkspace` — `../../etc/passwd`, an absolute path, and a path with a `..` segment in the middle: all refused, nothing extracted.
- `TestReadRefusesAModeOtherThan0600Or0700`.
- `TestRoundTripIsByteIdentical` — every file's bytes, including CRLF and trailing whitespace, survive `Build` then `Read`. The parser's whole promise is byte preservation; the transport must not be the thing that breaks it.
- `TestManifestCarriesNoHostname`.
- `FuzzReadSnapshot` — added to the Makefile's `FUZZ_TARGETS`, because `Read` parses attacker-supplied input. `TestMakefileFuzzTargetsCoverEveryFuzzFunction` will fail if it is not.

**Verification:** `go test ./internal/sync -run 'TestBuild|TestRead|TestRoundTrip' -v`; `make fuzz`.

## Task 4: Encryption

**Files:** create `internal/sync/crypto.go`, `internal/sync/crypto_test.go`.

**Interfaces:**

```go
type KDFParams struct { ID string; Salt []byte; Time, Memory uint32; Threads uint8 }

func Seal(plaintext []byte, passphrase string, params KDFParams, nonce []byte) ([]byte, error)
func Open(sealed []byte, passphrase string) ([]byte, error)
func DefaultParams(salt []byte) KDFParams
```

**Tests.**
- `TestSealThenOpenRoundTrips`.
- `TestOpenRefusesTheWrongPassphrase` — and the error names neither the passphrase nor any plaintext.
- `TestOpenRefusesATamperedCiphertext` — flip one bit anywhere, including in the header, and it fails. GCM gives this for the body; the header must be authenticated as additional data, or its parameters can be downgraded.
- `TestNonceIsNeverReused` — 1000 seals of the same plaintext produce 1000 distinct nonces and 1000 distinct ciphertexts.
- `TestHeaderIsForwardReadable` — a header with an unknown KDF id fails with a message saying the archive needs a newer version, not with a decryption error.

**Verification:** `go test ./internal/sync -run TestSeal -v`; `go test -race ./internal/sync`.

## Task 5: Plan, service, and the post-commit queue

**Files:** create `internal/sync/plan.go`, `internal/sync/service.go`, `internal/application/syncqueue.go` and their tests.

**Interfaces:**

```go
// Plan turns a decrypted snapshot and the current workspace into the exact
// transaction that would make this machine match it — or into a conflict.
func Plan(base Manifest, local map[string]string, remote Manifest,
    contents map[string][]byte) (storage.Request, []Conflict, error)
```

**What it must not change:** `storage` gains nothing. If `Plan` cannot be expressed with today's `Change`, `Move` and `Removal`, the design is wrong and should come back here rather than grow the storage layer.

**Tests.**
- `TestPlanProducesOneTransaction`.
- `TestPlanMarksPrivateKeysSkipBackup` — every change whose manifest entry has `secret: true` carries `SkipBackup: true`. Named explicitly because it is the one place a private key could be copied into `backups/`.
- `TestPlanSetsAPreconditionOnEveryChange` — a change with a zero `Precondition` would overwrite blind.
- `TestPlanDistinguishesDeletedThereFromCreatedHere` — the three-way rule of section 4, as a table.
- `TestPlanReportsAConflictInsteadOfChoosing` — a file changed on both sides yields a `Conflict`, no `Change`, and an empty request when it is the only difference.
- `TestPushRefusesWhenTheRemoteMoved` — the fake store returns `412`; nothing local changes and the error is a conflict, not a failure.
- `TestQueueDebouncesAndNeverBlocksCommit` — ten commits in a second produce one push, and `Commit` returns before the push starts.
- `TestPullRefusesASnapshotThatBreaksTheIncludeGraph` — the `Manager.Validate` hook rejects it and no file is written. This is the test that proves the pull inherited the existing safety rather than bypassing it.

**Verification:** `go test ./internal/sync ./internal/application -v`; `go test -race ./...`.

## Task 6: Routes, settings and the interface

**Files:** create `internal/httpserver/sync.go`, `web/src/sync/SyncPanel.tsx`, `web/e2e/sync.spec.ts`; modify `api/openapi.yaml`, `web/src/App.tsx`, `web/src/i18n/messages.ts`.

```
GET  /api/v1/sync            → SyncStatus   (configured, last sync, pending, conflicts)
PUT  /api/v1/sync/settings   → 204          (endpoint, bucket, credentials; action token)
POST /api/v1/sync/push       → SyncResult
POST /api/v1/sync/pull       → SavePreview  (the existing preview shape)
POST /api/v1/sync/resolve    → SavePreview
```

Credentials and the passphrase go to `internal/secret`, never to `metadata.json` and never into a response body. `SyncStatus` reports *that* credentials are configured, never any part of them.

**The panel** states, above the settings form and not behind a disclosure: *"Your private keys are in this snapshot. They are encrypted on this machine before they are uploaded, with the passphrase you enter here — Cloudflare never sees it. Lose the passphrase and the snapshot cannot be recovered by anyone, including you."*

**Tests.**
- `TestSyncSettingsNeverReturnsTheSecretAccessKey` and the passphrase equivalent, plus an acceptance-level sweep asserting neither appears in any response body or log line.
- e2e `sync.spec.ts` runs against a fake object store started by the test — a small `httptest`-style server the binary is pointed at with `-sync-endpoint`. It pushes, mutates the remote out from under the client, pulls, and asserts the conflict is shown rather than resolved. No test in this repository ever reaches Cloudflare.

**Verification:** `make verify-generated`; `npm test --prefix web`; `make e2e`.

## Acceptance Gate

```sh
gofmt -l .            # prints nothing
go vet ./...
make verify-generated # no diff
make test
make fuzz             # includes FuzzReadSnapshot
make e2e
```

Plus six statements, each with a named test above:

1. A push cannot overwrite a snapshot this machine has not seen.
2. A pull is one `storage.Request` and is refused by the existing validator if it would break the Include graph.
3. A private key is never written into `~/.ssh/ssh-ui/backups/` by a pull.
4. A malicious snapshot cannot write outside the workspace or widen a permission bit.
5. No credential and no passphrase appears in any response body, any log line, or any file under `~/.ssh`.
6. `go.mod` and `go.sum` are unchanged: this plan adds no module.

## Known Limitations

- **Conditional `PUT` on R2 is assumed and must be confirmed** (Task 2). If it turns out to be unavailable, the guarantee in section 3 weakens from a compare-and-swap to a narrow race and the UI must say so.
- **The whole snapshot is re-uploaded for a one-byte change.** Kilobytes, deliberately traded for atomicity.
- **Losing the passphrase loses the snapshot.** That is what end-to-end encryption means, and the panel says it in those words.
- **Anyone holding the bucket credentials holds every private key in ciphertext,** and can attack the passphrase offline for as long as they like. Argon2id raises the cost; it does not remove the exposure. A user who is not comfortable with that should keep keys out of the snapshot — which this design does not currently offer as a switch, and probably should.
- **No automatic pull.** Two machines edited between syncs will conflict at push time rather than merge continuously, which is the honest behaviour but not the seamless one.
- **`known_hosts` does not travel,** so a new machine must still verify host keys itself. Given the password-authentication plan makes a known host key a precondition, these two features interact: a freshly synced machine can see all its hosts and cannot yet use a stored password with any of them.
