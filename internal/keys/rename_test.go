package keys

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newRenameService builds a workspace holding one generated key pair and the
// configuration file that names it, which is the situation every rename is
// really about: the file has a name, and something else already depends on it.
func newRenameService(t *testing.T, configuration string) (*Service, string) {
	t.Helper()
	service, workspace := newTestService(t, newQueryRunner())
	if _, err := service.Generate(GenerateRequest{
		Algorithm:  AlgorithmEd25519,
		FileName:   "id_work",
		Comment:    "aida@laptop",
		Passphrase: []byte("correct horse"),
	}); err != nil {
		t.Fatalf("Generate error = %v", err)
	}
	if configuration != "" {
		if err := os.WriteFile(filepath.Join(workspace.Root(), "config"), []byte(configuration), 0o600); err != nil {
			t.Fatalf("write configuration: %v", err)
		}
	}
	return service, workspace.Root()
}

func TestRenameMovesThePairAndRewritesTheDirectiveThatNamesIt(t *testing.T) {
	service, root := newRenameService(t, "Host build\n\tIdentityFile ~/.ssh/id_work\n")

	result, err := service.Rename(RenameRequest{KeyID: ItemID("id_work"), NewName: "id_build"})
	if err != nil {
		t.Fatalf("Rename error = %v", err)
	}

	for _, name := range []string{"id_work", "id_work.pub"} {
		if _, statErr := os.Lstat(filepath.Join(root, name)); !errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("%s is still in the workspace: %v", name, statErr)
		}
	}
	for _, name := range []string{"id_build", "id_build.pub"} {
		if _, statErr := os.Lstat(filepath.Join(root, name)); statErr != nil {
			t.Errorf("%s was not created: %v", name, statErr)
		}
	}
	if result.ID != ItemID("id_build") || result.RelativePath != "id_build" {
		t.Errorf("result = %#v, want the identifier of the new path", result)
	}

	// The point of the operation: the configuration follows the file. A rename
	// that left "~/.ssh/id_work" behind would break authentication later, with
	// nothing on screen to connect the two events.
	contents, err := os.ReadFile(filepath.Join(root, "config"))
	if err != nil {
		t.Fatalf("read configuration: %v", err)
	}
	if string(contents) != "Host build\n\tIdentityFile ~/.ssh/id_build\n" {
		t.Errorf("configuration = %q, want the rewritten IdentityFile", contents)
	}
	if len(result.References) != 1 || result.References[0].To != "~/.ssh/id_build" {
		t.Errorf("references = %#v, want one rewritten IdentityFile", result.References)
	}
}

func TestRenameKeepsTheSpellingTheUserWrote(t *testing.T) {
	// Three spellings of the same file. OpenSSH resolves all of them, and the
	// user recognises the one they typed, so the rename swaps the name and
	// nothing else. Normalising them into one form would be an edit nobody
	// asked for, in a file the user reads.
	service, root := newRenameService(t, strings.Join([]string{
		"Host tilde",
		"\tIdentityFile ~/.ssh/id_work",
		"Host percent",
		"\tIdentityFile %d/.ssh/id_work",
		"Host certificate",
		"\tCertificateFile ~/.ssh/id_work.pub",
		"",
	}, "\n"))

	if _, err := service.Rename(RenameRequest{KeyID: ItemID("id_work"), NewName: "id_build"}); err != nil {
		t.Fatalf("Rename error = %v", err)
	}

	contents, err := os.ReadFile(filepath.Join(root, "config"))
	if err != nil {
		t.Fatalf("read configuration: %v", err)
	}
	for _, want := range []string{"~/.ssh/id_build", "%d/.ssh/id_build", "~/.ssh/id_build.pub"} {
		if !strings.Contains(string(contents), want) {
			t.Errorf("configuration = %q, want it to contain %q", contents, want)
		}
	}
	if strings.Contains(string(contents), "id_work") {
		t.Errorf("configuration = %q, want no reference to the old name", contents)
	}
}

func TestRenameLeavesEveryOtherByteOfTheConfigurationAlone(t *testing.T) {
	source := "# hand written\nHost build\n\tIdentityFile=~/.ssh/id_work  # the build key\n\tUser    ops\n"
	service, root := newRenameService(t, source)

	if _, err := service.Rename(RenameRequest{KeyID: ItemID("id_work"), NewName: "id_build"}); err != nil {
		t.Fatalf("Rename error = %v", err)
	}

	contents, err := os.ReadFile(filepath.Join(root, "config"))
	if err != nil {
		t.Fatalf("read configuration: %v", err)
	}
	want := strings.Replace(source, "id_work", "id_build", 1)
	if string(contents) != want {
		t.Errorf("configuration = %q, want %q", contents, want)
	}
}

func TestRenameRefusesWhenTheDestinationIsOccupied(t *testing.T) {
	service, root := newRenameService(t, "")
	if err := os.WriteFile(filepath.Join(root, "id_build.pub"), []byte("occupied\n"), 0o644); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	result, err := service.Rename(RenameRequest{KeyID: ItemID("id_work"), NewName: "id_build"})
	if !errors.Is(err, ErrRenameBlocked) {
		t.Fatalf("Rename error = %v, want ErrRenameBlocked", err)
	}
	if len(result.Blockers) != 1 || !strings.HasPrefix(result.Blockers[0], BlockerRenameTargetOccupied) {
		t.Errorf("blockers = %#v, want the occupied destination", result.Blockers)
	}
	// The private key is the file the operation was about, and it is untouched:
	// a blocked rename moves nothing at all, not even the part that would fit.
	if _, statErr := os.Lstat(filepath.Join(root, "id_work")); statErr != nil {
		t.Errorf("the key was moved by a blocked rename: %v", statErr)
	}
}

func TestRenameRefusesWhileADirectiveCannotBeResolved(t *testing.T) {
	// A relative IdentityFile is resolved by ssh against its own working
	// directory, which this application cannot know. It names "id_work", so it
	// may well be this key, and the rename refuses rather than leave a
	// reference it cannot see behind.
	service, _ := newRenameService(t, "Host build\n\tIdentityFile id_work\n")

	result, err := service.Rename(RenameRequest{KeyID: ItemID("id_work"), NewName: "id_build"})
	if !errors.Is(err, ErrRenameBlocked) {
		t.Fatalf("Rename error = %v, want ErrRenameBlocked", err)
	}
	if len(result.Blockers) != 1 || !strings.HasPrefix(result.Blockers[0], BlockerRenameUnresolved) {
		t.Errorf("blockers = %#v, want the unresolved directive", result.Blockers)
	}
}

func TestRenameIgnoresAnUnresolvedDirectiveThatCannotBeThisKey(t *testing.T) {
	// Both of these are unresolved, and neither can be the key being renamed:
	// one names a different file, and the other resolved to a definite path
	// outside ~/.ssh. Refusing on them would make the feature unusable for
	// anyone whose configuration is not already pristine.
	service, root := newRenameService(t, "Host other\n\tIdentityFile id_personal\n\tIdentityFile /etc/ssh/ssh_host_key\n")

	if _, err := service.Rename(RenameRequest{KeyID: ItemID("id_work"), NewName: "id_build"}); err != nil {
		t.Fatalf("Rename error = %v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(root, "id_build")); statErr != nil {
		t.Errorf("id_build was not created: %v", statErr)
	}
}

func TestRenameRefusesTheNameTheKeyAlreadyHas(t *testing.T) {
	service, _ := newRenameService(t, "")

	if _, err := service.Rename(RenameRequest{KeyID: ItemID("id_work"), NewName: "id_work"}); !errors.Is(err, ErrRenameUnchanged) {
		t.Fatalf("Rename error = %v, want ErrRenameUnchanged", err)
	}
}

func TestRenameRefusesAnUnsafeName(t *testing.T) {
	service, _ := newRenameService(t, "")

	for _, name := range []string{"../escape", "id_build.pub", "config", "", ".hidden"} {
		if _, err := service.Rename(RenameRequest{KeyID: ItemID("id_work"), NewName: name}); !errors.Is(err, ErrInvalidFileName) {
			t.Errorf("Rename(%q) error = %v, want ErrInvalidFileName", name, err)
		}
	}
}

func TestRenameRefusesHalfOfAPair(t *testing.T) {
	service, _ := newRenameService(t, "")

	if _, err := service.Rename(RenameRequest{KeyID: ItemID("id_work.pub"), NewName: "id_build"}); !errors.Is(err, ErrRenameNotSupported) {
		t.Fatalf("Rename error = %v, want ErrRenameNotSupported", err)
	}
}

func TestRenameRenamesAPublicKeyThatStandsAlone(t *testing.T) {
	service, root := newRenameService(t, "")
	lone, err := os.ReadFile(filepath.Join(root, "id_work.pub"))
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	for _, name := range []string{"id_work", "id_work.pub"} {
		if err := os.Remove(filepath.Join(root, name)); err != nil {
			t.Fatalf("remove %s: %v", name, err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "colleague.pub"), lone, 0o644); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	result, err := service.Rename(RenameRequest{KeyID: ItemID("colleague.pub"), NewName: "alex"})
	if err != nil {
		t.Fatalf("Rename error = %v", err)
	}
	// The suffix says what the file is, so it is kept: renaming to "alex" must
	// not produce a public key that no longer looks like one.
	if result.RelativePath != "alex.pub" {
		t.Errorf("relative path = %q, want alex.pub", result.RelativePath)
	}
	if _, statErr := os.Lstat(filepath.Join(root, "alex.pub")); statErr != nil {
		t.Errorf("alex.pub was not created: %v", statErr)
	}
	// Nothing to warn about: a public key carries no passphrase, so no Keychain
	// entry can be left naming the old path.
	if len(result.Notes) != 0 {
		t.Errorf("notes = %#v, want none for a public key", result.Notes)
	}
}

func TestRenameLeavesALookAlikeAloneAndSaysSo(t *testing.T) {
	service, root := newRenameService(t, "")
	public, err := os.ReadFile(filepath.Join(root, "id_work.pub"))
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	// Same key, a name of the user's own choosing. It is not "id_work" plus a
	// suffix, so renaming it would be this application deciding what the user
	// meant by a name they chose deliberately.
	if err := os.WriteFile(filepath.Join(root, "backup_copy.pub"), public, 0o644); err != nil {
		t.Fatalf("write sibling: %v", err)
	}

	result, err := service.Rename(RenameRequest{KeyID: ItemID("id_work"), NewName: "id_build"})
	if err != nil {
		t.Fatalf("Rename error = %v", err)
	}
	if len(result.Skipped) != 1 || result.Skipped[0] != "backup_copy.pub" {
		t.Errorf("skipped = %#v, want backup_copy.pub", result.Skipped)
	}
	if _, statErr := os.Lstat(filepath.Join(root, "backup_copy.pub")); statErr != nil {
		t.Errorf("backup_copy.pub was moved: %v", statErr)
	}
}

func TestRenameWarnsThatTheKeychainEntryStaysBehind(t *testing.T) {
	service, _ := newRenameService(t, "")

	result, err := service.Rename(RenameRequest{KeyID: ItemID("id_work"), NewName: "id_build"})
	if err != nil {
		t.Fatalf("Rename error = %v", err)
	}
	if len(result.Notes) != 1 || result.Notes[0] != NoteKeychainEntryStale {
		t.Errorf("notes = %#v, want the Keychain warning", result.Notes)
	}
}

func TestRenameKeepsThePermissionBitsAndCopiesNoKeyMaterial(t *testing.T) {
	service, workspace := newTestService(t, newQueryRunner())
	if _, err := service.Generate(GenerateRequest{
		Algorithm:  AlgorithmEd25519,
		FileName:   "id_work",
		Comment:    "aida@laptop",
		Passphrase: []byte("correct horse"),
	}); err != nil {
		t.Fatalf("Generate error = %v", err)
	}
	root := workspace.Root()
	if err := os.Chmod(filepath.Join(root, "id_work"), 0o400); err != nil {
		t.Fatalf("tighten permissions: %v", err)
	}

	if _, err := service.Rename(RenameRequest{KeyID: ItemID("id_work"), NewName: "id_build"}); err != nil {
		t.Fatalf("Rename error = %v", err)
	}

	info, err := os.Lstat(filepath.Join(root, "id_build"))
	if err != nil {
		t.Fatalf("renamed key missing: %v", err)
	}
	if info.Mode().Perm() != 0o400 {
		t.Errorf("permission = %04o, want the original 0400", info.Mode().Perm())
	}
	// A rename is a rename(2), so the bytes never move through this process and
	// never reach the generational backup directory.
	assertNoKeyMaterialInBackups(t, workspace)
}
