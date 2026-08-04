package macos_test

import (
	"context"
	"slices"
	"testing"

	"ssh-ui/internal/platform/macos"
)

type fakeRunner struct{ argv []string }

func (runner *fakeRunner) Run(_ context.Context, name string, args ...string) error {
	runner.argv = append([]string{name}, args...)
	return nil
}

func TestBrowserUsesOpenWithoutShell(t *testing.T) {
	runner := &fakeRunner{}
	browser := macos.NewBrowser(runner)
	target := "http://127.0.0.1:43123/#bootstrap=abc;$(touch%20/tmp/nope)"

	if err := browser.Open(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal([]string{"open", target}, runner.argv) {
		t.Fatalf("argv = %#v", runner.argv)
	}
}
