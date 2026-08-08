package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"

	"sshc/internal/application"
	"sshc/internal/effective"
)

const ConnectSubcommand = "connect"

var errTUIClosed = errors.New("connection picker closed")

type tuiHost struct {
	Alias     string
	Hostname  string
	User      string
	Port      string
	Tags      []string
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
	workspace, graph, err := readConfigGraph(home)
	if err != nil {
		return nil, err
	}
	favourites := map[string]bool{}
	tags := map[string][]string{}
	metadata, _, metadataErr := application.NewMetadataStore(workspace).Load()
	if metadataErr == nil {
		for _, host := range metadata.Hosts {
			if host.Favourite {
				favourites[host.Identity.Alias] = true
			}
			if len(host.Tags) != 0 {
				tags[host.Identity.Alias] = host.Tags
			}
		}
	}
	hosts := make([]tuiHost, 0)
	for _, alias := range concreteAliases(graph) {
		projection := effective.Project(graph, alias)
		host := tuiHost{
			Alias:     alias,
			Hostname:  alias,
			Tags:      tags[alias],
			Favourite: favourites[alias],
		}
		if value, ok := projection.Value("hostname"); ok {
			host.Hostname = value.Value
		}
		if value, ok := projection.Value("user"); ok {
			host.User = value.Value
		}
		if value, ok := projection.Value("port"); ok && value.Value != "22" {
			host.Port = value.Value
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

// destination は、接続先として ssh が使う値を、そのまま読める形で表す。
func (host tuiHost) destination() string {
	shown := host.Hostname
	if host.User != "" {
		shown = host.User + "@" + shown
	}
	if host.Port != "" {
		shown += ":" + host.Port
	}
	return shown
}

func filterTUIHosts(hosts []tuiHost, query string) []tuiHost {
	words := strings.Fields(strings.ToLower(query))
	if len(words) == 0 {
		return hosts
	}
	filtered := make([]tuiHost, 0, len(hosts))
	for _, host := range hosts {
		haystack := strings.ToLower(strings.Join(
			append([]string{host.Alias, host.Hostname, host.User, host.Port}, host.Tags...), " "))
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
}

func (model *tuiModel) visible() []tuiHost { return filterTUIHosts(model.hosts, model.query) }

func (model *tuiModel) move(by int) {
	target := model.selected + by
	count := len(model.visible())
	if target < 0 {
		target = 0
	}
	if target >= count {
		target = count - 1
	}
	if target < 0 {
		target = 0
	}
	model.selected = target
}

// feed は端末から届いた 1 回分の読み取りを消費し、選ばれた alias と、この画面を
// 終えるかどうかを返す。
//
// バイトごとではなくまとまりで扱うのは、Esc だけがそれ自体キーであり、同時に
// すべての矢印キーの先頭でもあるからだ。端末は矢印を 1 回の読み取りで届けるので、
// Esc が読み取りの最後のバイトであれば、それは Esc キーそのものである。1 バイト
// ずつ待つ設計では、この二つを区別する手段は時間しかない。
//
// 知らないシーケンスは終端バイトまで読み捨てる。そうしないと、Delete や Ctrl-矢印
// のような、こちらが扱わないキーの残骸が検索語に入る。
func (model *tuiModel) feed(chunk []byte) (string, bool) {
	for index := 0; index < len(chunk); index++ {
		value := chunk[index]
		if value == 27 {
			if index == len(chunk)-1 {
				return "", true
			}
			next := chunk[index+1]
			if next != '[' && next != 'O' {
				// Alt を伴う打鍵。扱わないので、その 1 文字ごと読み捨てる。
				index++
				continue
			}
			final, offset := escapeSequence(chunk[index+2:])
			if offset < 0 {
				// 終端が今回の読み取りに入っていない。残りは読み捨てる。
				break
			}
			index += 2 + offset
			switch final {
			case 'A':
				model.move(-1)
			case 'B':
				model.move(1)
			case 'H':
				model.selected = 0
			case 'F':
				model.move(len(model.visible()))
			}
			continue
		}
		if alias, done := model.key(value); done {
			return alias, true
		}
	}
	return "", false
}

// escapeSequence は CSI/SS3 の残りを読み、終端バイトとその位置を返す。終端は
// 0x40..0x7e であり、その手前にあるのはパラメータでしかない。終端が無ければ
// 位置は -1 で、それは読み取りがシーケンスの途中で切れたことを意味する。
func escapeSequence(rest []byte) (byte, int) {
	for offset, value := range rest {
		if value >= 0x40 && value <= 0x7e {
			return value, offset
		}
	}
	return 0, -1
}

func (model *tuiModel) key(value byte) (string, bool) {
	switch value {
	case 3: // Ctrl-C
		return "", true
	case 13, 10:
		visible := model.visible()
		if len(visible) != 0 && model.selected < len(visible) {
			return visible[model.selected].Alias, true
		}
	case 14: // Ctrl-N
		model.move(1)
	case 16: // Ctrl-P
		model.move(-1)
	case 21: // Ctrl-U
		model.query = ""
		model.selected = 0
	case 127, 8:
		if len(model.query) > 0 {
			// 末尾の 1 文字を消す。1 バイトではない。壊れた UTF-8 を作らない
			// ためであり、それは同じ端末がそのまま表示するものだからだ。
			_, size := utf8.DecodeLastRuneInString(model.query)
			model.query = model.query[:len(model.query)-size]
			model.selected = 0
		}
	default:
		// 制御文字だけを落とす。マルチバイトの文字はそのまま通す。バイトを
		// そのまま継ぎ足すのは、string(value) が 1 バイトを 1 つの rune として
		// 読み直してしまい、UTF-8 の途中のバイトが別の文字になるからである。
		if value >= 32 {
			model.query += string([]byte{value})
			model.selected = 0
		}
	}
	return "", false
}

// truncate は、行を端末の幅に収める。折り返した行は選択の反転表示を次の行へ
// こぼし、画面全体を崩すからである。
func truncate(line string, width int) string {
	if width <= 0 {
		return ""
	}
	if utf8.RuneCountInString(line) <= width {
		return line
	}
	if width == 1 {
		return "…"
	}
	runes := []rune(line)
	return string(runes[:width-1]) + "…"
}

func renderTUI(output io.Writer, model *tuiModel, width, height int) {
	var screen strings.Builder
	if width <= 0 {
		width = 80
	}
	all := model.visible()
	visible := all
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
	fmt.Fprintf(&screen, "\x1b[1m%s\x1b[0m\n", truncate("sshc connect", width))
	fmt.Fprintf(&screen, "\nSearch: \x1b[36m%s\x1b[0m\n\n", truncate(model.query, width-8))
	if len(visible) == 0 {
		fmt.Fprintln(&screen, truncate("  No matching hosts", width))
	}
	for index, host := range visible {
		line := fmt.Sprintf("  %-26s", host.Alias)
		if host.Favourite {
			line = "★ " + line[2:]
		}
		line += " " + host.destination()
		if len(host.Tags) != 0 {
			line += " [" + strings.Join(host.Tags, " ") + "]"
		}
		line = truncate(line, width)
		if start+index == model.selected {
			fmt.Fprintf(&screen, "\x1b[7m%s\x1b[0m\n", line)
		} else {
			fmt.Fprintln(&screen, line)
		}
	}
	// 一覧が画面に収まらないことは黙っていられない。見えている分がすべてだと
	// 読めてしまうからである。
	if hidden := len(all) - len(visible); hidden > 0 {
		fmt.Fprintf(&screen, "\x1b[2m%s\x1b[0m\n", truncate(fmt.Sprintf("  %d more", hidden), width))
	}
	fmt.Fprintf(&screen, "\n%s\n", truncate("Esc/Ctrl-C cancel  ↑/↓ select  Enter connect", width))
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
	// 端末はまとめて届ける。矢印キーは 3 バイトで、貼り付けはそれより遥かに長い。
	buffer := make([]byte, 1024)
	for {
		width, height, sizeErr := term.GetSize(int(output.Fd()))
		if sizeErr != nil {
			width, height = 80, 24
		}
		renderTUI(output, model, width, height)
		read, err := input.Read(buffer[:])
		if err != nil {
			fmt.Fprintf(stderr, "sshc: read terminal: %v\n", err)
			return "", err
		}
		alias, done := model.feed(buffer[:read])
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
