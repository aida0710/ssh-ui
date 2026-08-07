package remotesync_test

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"sshc/internal/remotesync"
	"sshc/internal/storage"
)

const root = "/Users/tester/.ssh"

func digestOf(contents string) string { return remotesync.Digest([]byte(contents)) }

func manifestOf(files ...remotesync.Entry) remotesync.Manifest {
	return remotesync.Manifest{SchemaVersion: remotesync.SchemaVersion, Files: files}
}

func file(path, contents string, secret bool) remotesync.Entry {
	return remotesync.Entry{Path: path, SHA256: digestOf(contents), Mode: "0600", Secret: secret}
}

func TestPlanProducesOneTransaction(t *testing.T) {
	remote := manifestOf(
		file("config", "new config", false),
		file("connections/work/lon.conf", "new host", false),
	)
	contents := map[string][]byte{
		"config":                    []byte("new config"),
		"connections/work/lon.conf": []byte("new host"),
	}
	base := manifestOf(file("config", "old config", false))
	local := map[string]string{"config": digestOf("old config")}

	request, conflicts, err := remotesync.Plan(root, &base, local, remote, contents)
	if err != nil {
		t.Fatalf("Plan = %v", err)
	}
	if len(conflicts) != 0 {
		t.Fatalf("conflicts = %#v", conflicts)
	}
	if request.Operation != "sync.pull" {
		t.Errorf("operation = %q", request.Operation)
	}
	if len(request.Changes) != 2 || len(request.Removals) != 0 {
		t.Fatalf("changes = %d, removals = %d", len(request.Changes), len(request.Removals))
	}
	if request.Changes[0].Path != filepath.Join(root, "config") {
		t.Errorf("path = %q", request.Changes[0].Path)
	}
}

func TestEveryChangeCarriesAPrecondition(t *testing.T) {
	// A change with a zero precondition would overwrite blind, which is the
	// one thing this application does not do anywhere else either.
	remote := manifestOf(file("config", "new", false))
	base := manifestOf(file("config", "old", false))
	local := map[string]string{"config": digestOf("old")}

	request, _, err := remotesync.Plan(root, &base, local, remote, map[string][]byte{"config": []byte("new")})
	if err != nil {
		t.Fatal(err)
	}
	change := request.Changes[0]
	if !change.Precondition.Exists || change.Precondition.Digest != digestOf("old") {
		t.Errorf("precondition = %#v, want the digest currently on disk", change.Precondition)
	}
}

func TestANewFileGetsAPreconditionThatItDoesNotExist(t *testing.T) {
	remote := manifestOf(file("connections/new.conf", "x", false))
	base := manifestOf()

	request, _, err := remotesync.Plan(root, &base, map[string]string{}, remote,
		map[string][]byte{"connections/new.conf": []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	if request.Changes[0].Precondition.Exists {
		t.Errorf("precondition = %#v, want the zero value for a file that is not there", request.Changes[0].Precondition)
	}
}

// A pull that overwrites a local private key keeps the previous one.
//
// It used to ask for no backup, because the copy would have been the key in the
// clear. The backups are sealed with the master password now, and this is
// exactly the case where the key that was replaced is what somebody wants
// back: a snapshot from another machine landing on top of a local key.
func TestPlanKeepsTheKeyAPullOverwrites(t *testing.T) {
	remote := manifestOf(
		file("config", "c", false),
		file("keys/work/id_ed25519", "private", true),
	)
	base := manifestOf()

	request, _, err := remotesync.Plan(root, &base, map[string]string{}, remote, map[string][]byte{
		"config":               []byte("c"),
		"keys/work/id_ed25519": []byte("private"),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range request.Changes {
		if change.SkipBackup {
			t.Errorf("%s asked for no backup, so the pull cannot be undone", change.Path)
		}
	}
}

func TestPlanDistinguishesDeletedThereFromCreatedHere(t *testing.T) {
	// The last-synced manifest is the only thing that can tell them apart, and
	// getting it wrong deletes a file the user just made.
	base := manifestOf(file("connections/gone.conf", "old", false))
	local := map[string]string{
		"connections/gone.conf": digestOf("old"),  // in the base, not in the remote → deleted there
		"connections/new.conf":  digestOf("mine"), // in neither → created here
	}
	remote := manifestOf(file("config", "c", false))

	request, conflicts, err := remotesync.Plan(root, &base, local, remote, map[string][]byte{"config": []byte("c")})
	if err != nil {
		t.Fatal(err)
	}
	if len(conflicts) != 0 {
		t.Fatalf("conflicts = %#v", conflicts)
	}
	if len(request.Removals) != 1 || request.Removals[0].Path != filepath.Join(root, "connections/gone.conf") {
		t.Fatalf("removals = %#v", request.Removals)
	}
	for _, removal := range request.Removals {
		if strings.Contains(removal.Path, "new.conf") {
			t.Error("a file created on this machine was scheduled for deletion")
		}
	}
}

func TestPlanReportsAConflictInsteadOfChoosing(t *testing.T) {
	// Changed on both sides. A merge of two ssh_config files that both changed
	// the same Host block has no correct answer, and guessing one would
	// violate the byte-preservation promise the parser exists to keep.
	base := manifestOf(file("config", "common ancestor", false))
	local := map[string]string{"config": digestOf("mine")}
	remote := manifestOf(file("config", "theirs", false))

	request, conflicts, err := remotesync.Plan(root, &base, local, remote, map[string][]byte{"config": []byte("theirs")})
	if err != nil {
		t.Fatal(err)
	}
	if len(request.Changes) != 0 || len(request.Removals) != 0 {
		t.Fatalf("a conflicted file was written anyway: %#v", request)
	}
	if len(conflicts) != 1 {
		t.Fatalf("conflicts = %#v", conflicts)
	}
	got := conflicts[0]
	if got.BaseDigest != digestOf("common ancestor") ||
		got.LocalDigest != digestOf("mine") ||
		got.RemoteDigest != digestOf("theirs") {
		t.Errorf("conflict = %#v", got)
	}
}

func TestAConflictCarriesNoContents(t *testing.T) {
	// A conflict record that carried a private key's bytes would be a copy of
	// that key in a response body.
	base := manifestOf(file("keys/id_ed25519", "ancestor", true))
	local := map[string]string{"keys/id_ed25519": digestOf("local key material")}
	remote := manifestOf(file("keys/id_ed25519", "remote key material", true))

	_, conflicts, err := remotesync.Plan(root, &base, local, remote,
		map[string][]byte{"keys/id_ed25519": []byte("remote key material")})
	if err != nil {
		t.Fatal(err)
	}
	if len(conflicts) != 1 {
		t.Fatalf("conflicts = %#v", conflicts)
	}
	for _, field := range []string{conflicts[0].BaseDigest, conflicts[0].LocalDigest, conflicts[0].RemoteDigest} {
		if strings.Contains(field, "key material") {
			t.Error("a conflict carries file contents")
		}
	}
}

func TestDeletedThereButEditedHereIsAConflict(t *testing.T) {
	base := manifestOf(file("config", "ancestor", false))
	local := map[string]string{"config": digestOf("edited here")}
	remote := manifestOf()

	request, conflicts, err := remotesync.Plan(root, &base, local, remote, map[string][]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if len(request.Removals) != 0 {
		t.Fatal("a file edited on this machine was deleted because the remote dropped it")
	}
	if len(conflicts) != 1 || conflicts[0].RemoteDigest != "" {
		t.Fatalf("conflicts = %#v", conflicts)
	}
}

func TestAFirstSyncDeletesNothing(t *testing.T) {
	// With no base manifest nothing can be called a deletion, so a machine
	// that has never synced cannot lose a file by pulling.
	local := map[string]string{"connections/local-only.conf": digestOf("mine")}
	remote := manifestOf(file("config", "c", false))

	request, conflicts, err := remotesync.Plan(root, nil, local, remote, map[string][]byte{"config": []byte("c")})
	if err != nil {
		t.Fatal(err)
	}
	if len(request.Removals) != 0 {
		t.Errorf("removals = %#v", request.Removals)
	}
	if len(conflicts) != 0 {
		t.Errorf("conflicts = %#v", conflicts)
	}
}

func TestAnIdenticalSnapshotIsNothingToApply(t *testing.T) {
	base := manifestOf(file("config", "same", false))
	local := map[string]string{"config": digestOf("same")}
	remote := manifestOf(file("config", "same", false))

	_, _, err := remotesync.Plan(root, &base, local, remote, map[string][]byte{"config": []byte("same")})
	if !errors.Is(err, remotesync.ErrNothingToApply) {
		t.Fatalf("Plan = %v, want ErrNothingToApply", err)
	}
}

func TestPlanNeedsNothingStorageDoesNotAlreadyHave(t *testing.T) {
	// If a pull could not be expressed with today's Change, Removal and
	// Request, the design would be wrong and should come back to the plan
	// rather than grow the storage layer. This asserts the shape it produces
	// is exactly that vocabulary.
	base := manifestOf(file("config", "old", false), file("gone.conf", "g", false))
	local := map[string]string{"config": digestOf("old"), "gone.conf": digestOf("g")}
	remote := manifestOf(file("config", "new", false))

	request, _, err := remotesync.Plan(root, &base, local, remote, map[string][]byte{"config": []byte("new")})
	if err != nil {
		t.Fatal(err)
	}
	var _ storage.Request = request
	if len(request.Moves) != 0 {
		t.Errorf("a pull produced moves, which it has no way to justify: %#v", request.Moves)
	}
}
