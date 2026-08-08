package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/term"

	"sshc/internal/application"
	"sshc/internal/effective"
	"sshc/internal/storage"
)

const ConnectSubcommand = "connect"

var errTUIClosed = errors.New("connection picker closed")

type tuiHost struct {
	Alias     string
	Hostname  string
	User      string
	Favourite bool
}

func tuiInvocation(argv []string) (string, bool) {
	if len(argv) < 2 || argv[1] != ConnectSubcommand {
		return "", false
	}
	if len(argv) == 3 {
		return argv[2], true
	}
	return "", true
}

func loadTUIHosts(home string) ([]tuiHost, error) {
	workspace, err := storage.NewWorkspace(storage.OSFileSystem{}, home)
	if err != nil {
		return nil, err
	}
	graph, err := storage.NewResolver(workspace).Resolve(filepath.Join(workspace.Root(), "config"))
	if err != nil {
		return nil, err
	}
	favourites := map[string]bool{}
	metadata, _, metadataErr := application.NewMetadataStore(workspace).Load()
	if metadataErr == nil {
		for _, host := range metadata.Hosts {
			if host.Favourite {
				favourites[host.Identity.Alias] = true
			}
		}
	}
	hosts := make([]tuiHost, 0)
	for _, alias := range concreteAliases(graph) {
		projection := effective.Project(graph, alias)
		host := tuiHost{Alias: alias, Hostname: alias, Favourite: favourites[alias]}
		if value, ok := projection.Value("hostname"); ok {
			host.Hostname = value.Value
		}
		if value, ok := projection.Value("user"); ok {
			host.User = value.Value
		}
		hosts = append(hosts, host)
	}
	sort.SliceStable(hosts, func(i, j int) bool {
		if hosts[i].Favourite != hosts[j].Favourite {
			return hosts[i].Favourite
		}
		return strings.ToLower(hosts[i].Alias) < strings.ToLower(hosts[j].Alias)
	})
	return hosts, nil
}

func filterTUIHosts(hosts []tuiHost, query string) []tuiHost {
	words := strings.Fields(strings.ToLower(query))
	if len(words) == 0 {
		return hosts
	}
	filtered := make([]tuiHost, 0, len(hosts))
	for _, host := range hosts {
		haystack := strings.ToLower(strings.Join([]string{host.Alias, host.Hostname, host.User}, " "))
		matched := true
		for _, word := range words {
			if !strings.Contains(haystack, word) {
				matched = false
				break
			}
		}
		if matched {
			filtered = append(filtered, host)
		}
	}
	return filtered
}

type tuiModel struct {
	hosts    []tuiHost
	query    string
	selected int
	escape   int
}

func (model *tuiModel) visible() []tuiHost { return filterTUIHosts(model.hosts, model.query) }

func (model *tuiModel) input(value byte) (string, bool) {
	if model.escape == 1 {
		if value == '[' {
			model.escape = 2
		} else {
			model.escape = 0
			return "", true
		}
		return "", false
	}
	if model.escape == 2 {
		model.escape = 0
		switch value {
		case 'A':
			if model.selected > 0 {
				model.selected--
			}
		case 'B':
			if model.selected+1 < len(model.visible()) {
				model.selected++
			}
		}
		return "", false
	}
	switch value {
	case 3: // Ctrl-C
		return "", true
	case 13, 10:
		visible := model.visible()
		if len(visible) != 0 && model.selected < len(visible) {
			return visible[model.selected].Alias, true
		}
	case 14: // Ctrl-N
		if model.selected+1 < len(model.visible()) {
			model.selected++
		}
	case 16: // Ctrl-P
		if model.selected > 0 {
			model.selected--
		}
	case 21: // Ctrl-U
		model.query = ""
		model.selected = 0
	case 127, 8:
		if len(model.query) > 0 {
			model.query = model.query[:len(model.query)-1]
			model.selected = 0
		}
	case 27: // escape sequence or Esc followed by another key
		model.escape = 1
	default:
		if value >= 32 && value < 127 {
			model.query += string(value)
			model.selected = 0
		}
	}
	return "", false
}

func renderTUI(output io.Writer, model *tuiModel, height int) {
	var screen strings.Builder
	visible := model.visible()
	limit := height - 7
	if limit < 3 {
		limit = 3
	}
	start := 0
	if len(visible) > limit {
		if model.selected >= limit {
			start = model.selected - limit + 1
		}
		visible = visible[start : start+limit]
	}
	fmt.Fprint(&screen, "\x1b[H\x1b[2J")
	fmt.Fprintln(&screen, "\x1b[1msshc connect\x1b[0m")
	fmt.Fprintf(&screen, "\nSearch: \x1b[36m%s\x1b[0m\n\n", model.query)
	if len(visible) == 0 {
		fmt.Fprintln(&screen, "  No matching hosts")
	}
	for index, host := range visible {
		line := fmt.Sprintf("  %-26s", host.Alias)
		if host.Favourite {
			line = "★ " + line[2:]
		}
		destination := host.Hostname
		if host.User != "" {
			destination = host.User + "@" + destination
		}
		line += " " + destination
		if start+index == model.selected {
			fmt.Fprintf(&screen, "\x1b[7m%s\x1b[0m\n", line)
		} else {
			fmt.Fprintln(&screen, line)
		}
	}
	fmt.Fprintln(&screen, "\n↑/↓ select  Enter connect  Ctrl-C cancel")
	_, _ = io.WriteString(output, strings.ReplaceAll(screen.String(), "\n", "\r\n"))
}

func chooseTUIHost(home, initialQuery string, input, output *os.File, stderr io.Writer) (string, error) {
	if !term.IsTerminal(int(input.Fd())) || !term.IsTerminal(int(output.Fd())) {
		return "", errors.New("sshc connect requires an interactive terminal")
	}
	hosts, err := loadTUIHosts(home)
	if err != nil {
		return "", err
	}
	if len(hosts) == 0 {
		return "", errors.New("no concrete Host aliases were found")
	}
	state, err := term.MakeRaw(int(input.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Fprint(output, "\x1b[?1049h\x1b[?25l")
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		fmt.Fprint(output, "\x1b[?25h\x1b[?1049l")
		_ = term.Restore(int(input.Fd()), state)
	}
	defer restore()

	model := &tuiModel{hosts: hosts, query: initialQuery}
	for {
		_, height, sizeErr := term.GetSize(int(output.Fd()))
		if sizeErr != nil {
			height = 24
		}
		renderTUI(output, model, height)
		var buffer [1]byte
		if _, err := input.Read(buffer[:]); err != nil {
			fmt.Fprintf(stderr, "sshc: read terminal: %v\n", err)
			return "", err
		}
		alias, done := model.input(buffer[0])
		if !done {
			continue
		}
		restore()
		if alias == "" {
			return "", errTUIClosed
		}
		return alias, nil
	}
}
