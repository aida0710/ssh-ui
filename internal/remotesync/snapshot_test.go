package remotesync_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"sshc/internal/remotesync"
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
		"sshc/metadata.json":        []byte(`{"schemaVersion":2}`),
		"keys/work/id_ed25519":      []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nnot really\n"),
	}
	manifest := remotesync.Manifest{
		CreatedAt: "2026-08-05T00:00:00Z",
		Origin:    "opaque-installation-id",
		Files: []remotesync.Entry{
			entry("config", string(contents["config"]), false),
			entry("connections/work/lon.conf", string(contents["connections/work/lon.conf"]), false),
			entry("sshc/metadata.json", string(contents["sshc/metadata.json"]), false),
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
	// パーサの約束のすべてはバイト保存である。トランスポートがそれを壊すものであっては
	// ならないので、フィクスチャには CRLF、末尾の空白、そして末尾に改行のないファイルを
	// 含めてある。
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
	// pull は secret のエントリを SkipBackup 付きで適用する。この印を失えば、同期の
	// たびに ~/.ssh/sshc/backups/ に鍵素材のコピーが残ることになる。
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
	// このフィールドはインストールを区別するためにあり、マシンを名指しするためではない。
	document, _ := json.Marshal(manifest)
	for _, forbidden := range []string{"hostname", "Hostname", ".local"} {
		if bytes.Contains(document, []byte(forbidden)) {
			t.Errorf("the manifest carries %q", forbidden)
		}
	}
}

func TestReadRefusesAPathThatEscapesTheWorkspace(t *testing.T) {
	// スナップショットは信用できない入力であり、tar の中の "../" は最も古い手口で
	// ある。
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
	// 拒否する代わりに正規化すれば、スナップショットは秘密鍵の権限を、OpenSSH はまだ
	// 読むが他のユーザーも読める程度まで広げられてしまう。
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
	// マニフェストは、pull がローカルのディスクと比較する対象である。ファイルがそれと
	// 食い違うスナップショットは、ある一組のダイジェストから組み立てられ、別の一組から
	// 適用されるトランザクションを生んでしまう。
	archive := handBuilt(t, map[string]string{"config": "actual"}, remotesync.Manifest{
		Files: []remotesync.Entry{{Path: "config", SHA256: remotesync.Digest([]byte("claimed")), Mode: "0600"}},
	})
	if _, _, err := remotesync.Read(archive); !errors.Is(err, remotesync.ErrManifestMismatch) {
		t.Fatalf("Read = %v, want ErrManifestMismatch", err)
	}

	// アーカイブに存在するがマニフェストにないファイルは、同じ欠陥を逆方向から見たもの
	// である。それは検査されずに展開されてしまう。
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
	// Read は攻撃者由来の入力を解析する。アーカイブはバケットから来るのであり、その
	// バケットに書ける者が、その中身を選ぶ。
	archive, _ := buildFixture(&testing.T{})
	f.Add(archive)
	f.Add([]byte{})
	f.Add([]byte("not gzip at all"))

	f.Fuzz(func(t *testing.T, input []byte) {
		manifest, contents, err := remotesync.Read(input)
		if err != nil {
			return
		}
		// 解析を通るものはすべて、ファイルシステムに触れる前に、呼び出し側が依拠する
		// あらゆる不変条件を満たさなければならない。
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

// handBuilt は Build を通さずにアーカイブを書く。これにより、Build なら拒否する
// ものをテストがその中に入れられる。
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
	// まずマニフェスト、そのあとに他のすべて。Build が使うのと同じ順序である。
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

// スナップショットが保持してよいのはファイルだけである。
//
// tar の中のシンボリックリンクは、展開器に、自分が書いていると思っている場所の外へ
// 書かせる最も古い手口だ。リンクは内側に作られ、それを通して書かれる次のエントリが、
// リンクの指す先へ着地する。それを拒否する検査はずっとそこにあったのに、取り除かれた
// ときに誰も気づかなかった。それは、その検査を持っていないのと同じことで
// ある。
func TestOpenRefusesAnEntryThatIsNotAFile(t *testing.T) {
	for _, entry := range []struct {
		name   string
		header tar.Header
	}{
		{"symlink", tar.Header{Typeflag: tar.TypeSymlink, Name: "escape", Linkname: "../../../etc/hosts"}},
		{"hard link", tar.Header{Typeflag: tar.TypeLink, Name: "escape", Linkname: "config"}},
		{"directory", tar.Header{Typeflag: tar.TypeDir, Name: "connections/", Mode: 0o700}},
		{"device", tar.Header{Typeflag: tar.TypeChar, Name: "console", Mode: 0o600}},
	} {
		t.Run(entry.name, func(t *testing.T) {
			var compressed bytes.Buffer
			zip := gzip.NewWriter(&compressed)
			archive := tar.NewWriter(zip)
			manifest := `{"schemaVersion":1,"createdAt":"2026-08-05T00:00:00Z","origin":"o","files":[]}`
			writeRaw(t, archive, remotesync.ManifestName, manifest)
			if err := archive.WriteHeader(&entry.header); err != nil {
				t.Fatal(err)
			}
			if err := archive.Close(); err != nil {
				t.Fatal(err)
			}
			if err := zip.Close(); err != nil {
				t.Fatal(err)
			}

			if _, _, err := remotesync.Read(compressed.Bytes()); !errors.Is(err, remotesync.ErrUnsafePath) {
				t.Errorf("a %s entry was accepted: %v", entry.name, err)
			}
		})
	}
}
