// Package selfupdate は、プロジェクトの GitHub リリースを調べ、より新しいものが
// あるかを伝える。
//
// 調べるだけで、それ以上は何もしない。以前はリリースを取得して自分が実行して
// いるバイナリを置き換えており、その保護は、コンパイル時に埋め込んだ公開鍵による
// チェックサムファイルへの署名だった — だがその保護はほとんど価値がなかった。
// 鍵はリリースワークフローが読める場所に置く必要があり、それはリポジトリを
// 支配できる者なら誰でも読める場所だからである。防御と攻撃が同じ鍵を持って
// いた。
//
// 残っているのは、危険な半分を除いた有用な半分だ。より新しいバージョンが存在する
// ことと、それについてどこで読めるかを伝え、判断は人がする。このアプリケーション
// のなかで自分自身以外のホストに接触する唯一の機能であり、定期実行ではなく求め
// られたときだけ動き、何もダウンロードしない。
package selfupdate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// ErrNoRelease は、プロジェクトがまだ何も公開していないことを報告する。
var ErrNoRelease = errors.New("no release has been published")

// Release は、プロジェクトが公開したもの。
type Release struct {
	Version string
	// PageURL は、何が変わったかを人が読み、どうするかを決める場所。これが提供する
	// もののすべてである。
	PageURL string
}

// Checker は、最新リリースが何かを GitHub に尋ねる。
type Checker struct {
	// API はリリースのエンドポイント。テストが GitHub に到達しないよう注入する。
	API  string
	HTTP *http.Client
}

type githubRelease struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
	Draft   bool   `json:"draft"`
}

func (c Checker) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

// Latest は、公開されている最も新しいリリースを返す。
func (c Checker) Latest(ctx context.Context) (Release, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.API, nil)
	if err != nil {
		return Release{}, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	response, err := c.client().Do(request)
	if err != nil {
		return Release{}, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusNotFound {
		return Release{}, ErrNoRelease
	}
	if response.StatusCode != http.StatusOK {
		return Release{}, fmt.Errorf("the releases API answered %d", response.StatusCode)
	}

	var decoded githubRelease
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&decoded); err != nil {
		return Release{}, err
	}
	if decoded.Draft || decoded.TagName == "" {
		return Release{}, ErrNoRelease
	}
	return Release{Version: decoded.TagName, PageURL: decoded.HTMLURL}, nil
}

// Newer は、candidate が current より後のバージョンかを報告する。
//
// バージョンはフィールドごとに数値として比較するので、0.10.0 は 0.9.0 より新しい
// — 文字列比較ではこれを取り違え、ここで取り違えれば、後戻りする更新を提示する
// ことになる。解析できないものは「より新しい」ではなく「異なる」として比較する。
// リリースでないビルド（"dev"）には、リリースがあることは伝えるべきだが、どれだけ
// 遅れているかを伝えてはならない。
func Newer(current, candidate string) bool {
	if current == candidate {
		return false
	}
	currentParts, currentOK := parseVersion(current)
	candidateParts, candidateOK := parseVersion(candidate)
	if !currentOK || !candidateOK {
		return true
	}
	for index := range currentParts {
		if candidateParts[index] != currentParts[index] {
			return candidateParts[index] > currentParts[index]
		}
	}
	return false
}

func parseVersion(value string) ([3]int, bool) {
	var parts [3]int
	fields := strings.Split(strings.TrimPrefix(strings.TrimSpace(value), "v"), ".")
	if len(fields) != 3 {
		return parts, false
	}
	for index, field := range fields {
		number, err := strconv.Atoi(field)
		if err != nil || number < 0 {
			return parts, false
		}
		parts[index] = number
	}
	return parts, true
}

func (c Checker) download(ctx context.Context, url string, limit int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	response, err := c.client().Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the download answered %d", response.StatusCode)
	}
	return io.ReadAll(io.LimitReader(response.Body, limit))
}
