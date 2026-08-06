package macos

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"ssh-ui/internal/platform"
)

// LoginItemLabel is the launchd label this application registers under.
const LoginItemLabel = "com.github.aida0710.ssh-ui"

// ErrLoginItemPathNotAbsolute refuses to register a program launchd would have
// to find through PATH, which is to say a program someone else could supply.
var ErrLoginItemPathNotAbsolute = errors.New("login item program path must be absolute")

// LoginItem turns "start ssh-ui when I log in" on and off.
//
// It is off unless the user asks for it. A background process that holds the
// key to every stored secret is not something to arrange on somebody's behalf,
// and the application is perfectly usable without it: `ssh-ui <alias>` falls
// back to a plain ssh when nothing is running.
//
// The agent is started with -open=false, so nothing opens a browser at login.
// Standard output is deliberately not redirected anywhere: it carries the URL
// with a live bootstrap token, and a log file is not a place for one. `ssh-ui
// open` mints a fresh one when somebody wants to look.
type LoginItem struct {
	// Runner runs launchctl. Injected so no test loads an agent.
	Runner platform.OutputRunner
	// Home is the user's home directory, which is where LaunchAgents live.
	Home string
	// Launchctl is the program, for a test that wants to see the argv.
	Launchctl string
}

func (l LoginItem) plistPath() string {
	return filepath.Join(l.Home, "Library", "LaunchAgents", LoginItemLabel+".plist")
}

// Enabled reports whether the agent is registered.
func (l LoginItem) Enabled() bool {
	_, err := os.Stat(l.plistPath())
	return err == nil
}

// Enable writes the agent and asks launchd to take it.
func (l LoginItem) Enable(ctx context.Context, program string) error {
	if !filepath.IsAbs(program) {
		return ErrLoginItemPathNotAbsolute
	}
	path := l.plistPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(agentPlist(program)), 0o600); err != nil {
		return err
	}
	// bootout first so a change to the program path is picked up rather than
	// leaving the previous one loaded.
	_ = l.launchctl(ctx, "bootout", l.domain()+"/"+LoginItemLabel)
	return l.launchctl(ctx, "bootstrap", l.domain(), path)
}

// Disable stops the agent and takes the file away.
func (l LoginItem) Disable(ctx context.Context) error {
	_ = l.launchctl(ctx, "bootout", l.domain()+"/"+LoginItemLabel)
	if err := os.Remove(l.plistPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (l LoginItem) domain() string {
	return "gui/" + strconv.Itoa(os.Getuid())
}

func (l LoginItem) launchctl(ctx context.Context, arguments ...string) error {
	program := l.Launchctl
	if program == "" {
		program = "/bin/launchctl"
	}
	if l.Runner == nil {
		return errors.New("no runner to start launchctl with")
	}
	_, err := l.Runner.RunOutput(ctx, platform.Command{Path: program, Arguments: arguments})
	return err
}

// agentPlist is the property list launchd reads.
//
// The program path is XML-escaped rather than concatenated raw: it comes from
// os.Executable and is not user input, but a path with an ampersand in it would
// otherwise produce a file launchd refuses to parse.
func agentPlist(program string) string {
	escape := func(value string) string {
		replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
		return replacer.Replace(value)
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>-open=false</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ProcessType</key>
	<string>Background</string>
</dict>
</plist>
`, LoginItemLabel, escape(program))
}
