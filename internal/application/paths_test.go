package application

import (
	"errors"
	"testing"
)

func TestRelativePathRejectsEverythingOutsideTheRoot(t *testing.T) {
	const root = "/home/tester/.ssh"
	tests := []struct {
		name     string
		absolute string
		want     string
		wantErr  bool
	}{
		{"root child", "/home/tester/.ssh/config", "config", false},
		{"nested child", "/home/tester/.ssh/conf.d/10-home.conf", "conf.d/10-home.conf", false},
		{"uncleaned child", "/home/tester/.ssh/conf.d/../config", "config", false},
		{"the root itself", "/home/tester/.ssh", "", true},
		{"sibling directory", "/home/tester/.sshother/config", "", true},
		{"escaping parent", "/home/tester/.ssh/../.bashrc", "", true},
		{"unrelated absolute", "/etc/ssh/ssh_config", "", true},
		{"relative input", "conf.d/10-home.conf", "", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			relative, err := RelativePath(root, test.absolute)
			if test.wantErr {
				if !errors.Is(err, ErrExternalPath) {
					t.Fatalf("RelativePath(%q) = %q, %v; want ErrExternalPath", test.absolute, relative, err)
				}
				return
			}
			if err != nil || relative != test.want {
				t.Fatalf("RelativePath(%q) = %q, %v; want %q", test.absolute, relative, err, test.want)
			}
		})
	}
}

func TestAbsolutePathRefusesTraversalAndAbsoluteInput(t *testing.T) {
	const root = "/home/tester/.ssh"
	absolute, err := AbsolutePath(root, "conf.d/10-home.conf")
	if err != nil || absolute != "/home/tester/.ssh/conf.d/10-home.conf" {
		t.Fatalf("AbsolutePath = %q, %v", absolute, err)
	}
	for _, relative := range []string{"", ".", "..", "../.bashrc", "conf.d/../../escape", "/etc/passwd", "conf.d//../../x"} {
		if _, err := AbsolutePath(root, relative); !errors.Is(err, ErrExternalPath) {
			t.Errorf("AbsolutePath(%q) error = %v, want ErrExternalPath", relative, err)
		}
	}
}
