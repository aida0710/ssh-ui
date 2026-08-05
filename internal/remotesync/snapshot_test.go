package remotesync_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"ssh-ui/internal/remotesync"
)

func entry(path, contents string, secret bool) remotesync.Entry {
	return remotesync.Entry{
		Path:   path,
		SHA256: remotesync.Digest([]byte(contents)),
		Mode:   "0600",
		Secret: secret,
	}
}

func buildFixture(t *testing.T) ([]byte, map[string][]byte) {
	t.Helper()
	contents := map[string][]byte{
		"config":                    []byte("# Managed by hand\r\nHost bastion\n\tPort 2222   \n"),
		"connections/work/lon.conf": []byte("Host lon-1\n\tHostName 203.0.113.11\n"),
		"ssh-ui/metadata.json":      []byte(`{"schemaVersion":2}`),
		"keys/work/id_ed25519":      []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nnot really\n"),
	}
	manifest := remotesync.Manifest{
		CreatedAt: "2026-08-05T00:00:00Z",
		Origin:    "opaque-installation-id",
		Files: []remotesync.Entry{
			entry("config", string(contents["config"]), false),
			entry("connections/work/lon.conf", string(contents["connections/work/lon.conf"]), false),
			entry("ssh-ui/metadata.json", string(contents["ssh-ui/metadata.json"]), false),
			entry("keys/work/id_ed25519", string(contents["keys/work/id_ed25519"]), true),
		},
	}
	archive, err := remotesync.Build(manifest, contents)
	if err != nil {
		t.Fatalf("Build = %v", err)
	}
	return archive, contents
}

func TestRoundTripIsByteIdentical(t *testing.T) {
	// The parser's whole promise is byte preservation. The transport must not
	// be the thing that breaks it, so the fixture carries a CRLF, trailing
	// spaces and a file with no trailing newline.
	archive, contents := buildFixture(t)

	manifest, unpacked, err := remotesync.Read(archive)
	if err != nil {
		t.Fatalf("Read = %v", err)
	}
	if len(unpacked) != len(contents) {
		t.Fatalf("unpacked %d files, want %d", len(unpacked), len(contents))
	}
	for path, want := range contents {
		if !bytes.Equal(unpacked[path], want) {
			t.Errorf("%s round tripped as %q, want %q", path, unpacked[path], want)
		}
	}
	if manifest.SchemaVersion != remotesync.SchemaVersion {
		t.Errorf("schema version = %d", manifest.SchemaVersion)
	}
}

func TestAPrivateKeyIsMarkedSecret(t *testing.T) {
	// A pull applies a secret entry with SkipBackup set. Losing the mark would
	// leave a copy of key material in ~/.ssh/ssh-ui/backups/ on every sync.
	archive, _ := buildFixture(t)

	manifest, _, err := remotesync.Read(archive)
	if err != nil {
		t.Fatal(err)
	}
	secrets := 0
	for _, item := range manifest.Files {
		if item.Secret {
			secrets++
			if !strings.HasPrefix(item.Path, "keys/") {
				t.Errorf("%s is marked secret", item.Path)
			}
		}
	}
	if secrets != 1 {
		t.Errorf("%d entries marked secret, want 1", secrets)
	}
}

func TestManifestCarriesNoHostname(t *testing.T) {
	archive, _ := buildFixture(t)
	manifest, _, err := remotesync.Read(archive)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Origin == "" {
		t.Error("no origin at all, so the interface cannot say where a snapshot came from")
	}
	// The field exists to distinguish installations, not to name machines.
	document, _ := json.Marshal(manifest)
	for _, forbidden := range []string{"hostname", "Hostname", ".local"} {
		if bytes.Contains(document, []byte(forbidden)) {
			t.Errorf("the manifest carries %q", forbidden)
		}
	}
}

func TestReadRefusesAPathThatEscapesTheWorkspace(t *testing.T) {
	// A snapshot is untrusted input and "../" in a tar is the oldest trick
	// there is.
	for _, name := range []string{
		"../../etc/passwd",
		"/etc/passwd",
		"connections/../../outside.conf",
		"./config",
		"a//b",
		"..",
		"",
		`windows\\path`,
	} {
		t.Run(name, func(t *testing.T) {
			archive := handBuilt(t, map[string]string{name: "x"}, remotesync.Manifest{
				Files: []remotesync.Entry{{Path: name, SHA256: remotesync.Digest([]byte("x")), Mode: "0600"}},
			})
			if _, _, err := remotesync.Read(archive); !errors.Is(err, remotesync.ErrUnsafePath) {
				t.Fatalf("Read = %v, want ErrUnsafePath", err)
			}
		})
	}
}

func TestReadRefusesAModeThisApplicationDoesNotWrite(t *testing.T) {
	// Normalising instead of refusing would let a snapshot widen a private key
	// to something OpenSSH still reads but other users can too.
	for _, mode := range []string{"0644", "0666", "0777", "0400", "", "not a mode"} {
		archive := handBuilt(t, map[string]string{"config": "x"}, remotesync.Manifest{
			Files: []remotesync.Entry{{Path: "config", SHA256: remotesync.Digest([]byte("x")), Mode: mode}},
		})
		if _, _, err := remotesync.Read(archive); !errors.Is(err, remotesync.ErrUnsafeMode) {
			t.Errorf("mode %q gave %v, want ErrUnsafeMode", mode, err)
		}
	}
}

func TestReadRefusesContentsThatDoNotMatchTheManifest(t *testing.T) {
	// The manifest is what a pull compares against the local disk. A snapshot
	// whose files disagree with it would produce a transaction built from one
	// set of digests and applied from another.
	archive := handBuilt(t, map[string]string{"config": "actual"}, remotesync.Manifest{
		Files: []remotesync.Entry{{Path: "config", SHA256: remotesync.Digest([]byte("claimed")), Mode: "0600"}},
	})
	if _, _, err := remotesync.Read(archive); !errors.Is(err, remotesync.ErrManifestMismatch) {
		t.Fatalf("Read = %v, want ErrManifestMismatch", err)
	}

	// A file present in the archive but absent from the manifest is the same
	// defect from the other direction: it would be extracted unchecked.
	extra := handBuilt(t, map[string]string{"config": "x", "stowaway": "y"}, remotesync.Manifest{
		Files: []remotesync.Entry{{Path: "config", SHA256: remotesync.Digest([]byte("x")), Mode: "0600"}},
	})
	if _, _, err := remotesync.Read(extra); !errors.Is(err, remotesync.ErrManifestMismatch) {
		t.Fatalf("Read = %v, want ErrManifestMismatch", err)
	}
}

func TestReadRefusesSomethingThatIsNotASnapshot(t *testing.T) {
	cases := map[string][]byte{
		"empty":        {},
		"not gzip":     []byte("plain text"),
		"gzip only":    gzipOf(t, nil),
		"no manifest":  handBuiltWithoutManifest(t),
		"random bytes": bytes.Repeat([]byte{0x9f}, 512),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := remotesync.Read(input); err == nil {
				t.Fatal("Read succeeded")
			}
		})
	}
}

func TestReadSaysUpgradeForASnapshotFromANewerBuild(t *testing.T) {
	archive := handBuilt(t, map[string]string{}, remotesync.Manifest{SchemaVersion: remotesync.SchemaVersion + 1})
	if _, _, err := remotesync.Read(archive); !errors.Is(err, remotesync.ErrUnsupportedVersion) {
		t.Fatalf("Read = %v, want ErrUnsupportedVersion", err)
	}
}

func TestBuildRefusesAnEntryWithNoContents(t *testing.T) {
	_, err := remotesync.Build(remotesync.Manifest{
		Files: []remotesync.Entry{{Path: "config", SHA256: "x", Mode: "0600"}},
	}, map[string][]byte{})
	if !errors.Is(err, remotesync.ErrManifestMismatch) {
		t.Fatalf("Build = %v, want ErrManifestMismatch", err)
	}
}

func FuzzReadSnapshot(f *testing.F) {
	// Read parses attacker-supplied input: the archive comes from a bucket,
	// and anyone who can write that bucket chooses what is in it.
	archive, _ := buildFixture(&testing.T{})
	f.Add(archive)
	f.Add([]byte{})
	f.Add([]byte("not gzip at all"))

	f.Fuzz(func(t *testing.T, input []byte) {
		manifest, contents, err := remotesync.Read(input)
		if err != nil {
			return
		}
		// Anything that parses must satisfy every invariant a caller relies on
		// before it touches a filesystem.
		for _, item := range manifest.Files {
			if strings.HasPrefix(item.Path, "/") || strings.Contains(item.Path, "..") {
				t.Fatalf("an unsafe path survived: %q", item.Path)
			}
			if item.Mode != "0600" && item.Mode != "0700" {
				t.Fatalf("an unsafe mode survived: %q", item.Mode)
			}
			if remotesync.Digest(contents[item.Path]) != item.SHA256 {
				t.Fatalf("a digest mismatch survived for %q", item.Path)
			}
		}
		if len(contents) != len(manifest.Files) {
			t.Fatalf("%d files and %d manifest entries", len(contents), len(manifest.Files))
		}
	})
}

// handBuilt writes an archive without going through Build, so a test can put
// something in it that Build would refuse.
func handBuilt(t *testing.T, files map[string]string, manifest remotesync.Manifest) []byte {
	t.Helper()
	if manifest.SchemaVersion == 0 {
		manifest.SchemaVersion = remotesync.SchemaVersion
	}
	document, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	entries := map[string]string{remotesync.ManifestName: string(document)}
	for name, body := range files {
		entries[name] = body
	}
	return archiveOf(t, entries)
}

func handBuiltWithoutManifest(t *testing.T) []byte {
	t.Helper()
	return archiveOf(t, map[string]string{"config": "Host x\n"})
}

func archiveOf(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var compressed bytes.Buffer
	zip := gzip.NewWriter(&compressed)
	archive := tar.NewWriter(zip)
	// The manifest first, then everything else, which is the order Build uses.
	if body, ok := entries[remotesync.ManifestName]; ok {
		writeRaw(t, archive, remotesync.ManifestName, body)
	}
	for name, body := range entries {
		if name == remotesync.ManifestName {
			continue
		}
		writeRaw(t, archive, name, body)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zip.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func writeRaw(t *testing.T, archive *tar.Writer, name, body string) {
	t.Helper()
	if err := archive.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg, Name: name, Mode: 0o600, Size: int64(len(body)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
}

func gzipOf(t *testing.T, body []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	zip := gzip.NewWriter(&buffer)
	if _, err := zip.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := zip.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
