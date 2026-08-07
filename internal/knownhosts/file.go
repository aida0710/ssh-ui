// Package knownhosts は、ユーザーの known_hosts ファイルを読み書きする。
//
// 解析は無損失である。変更していないファイルは 1 バイト違わず元に戻るので、削除は
// 求められた行だけを正確に取り除き、それ以外には手を触れない。書き込みはすべて
// ストレージのトランザクションマネージャを通る。
package knownhosts

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

// ErrInvalidKey は、鍵のブロブが妥当な base64 でないことを報告する。
var ErrInvalidKey = errors.New("public key is not valid base64")

// Entry は、解析済みの known_hosts レコードひとつ。
type Entry struct {
	Marker      string
	Hosts       []string
	Hashed      bool
	KeyType     string
	Key         string
	Fingerprint string
	Comment     string
}

// Line は物理行ひとつ。空行、コメント、そしてこのパッケージが解析できなかった行
// では Entry が nil になる。そうした行はそのまま逐語的に保存される。
type Line struct {
	Number  int
	Raw     string
	Ending  string
	Entry   *Entry
	Problem string
}

// File は、解析済みの known_hosts ファイル。
type File struct {
	Lines []Line
}

// ParseFile は contents を行に分割し、エントリを解析する。
func ParseFile(contents []byte) *File {
	file := &File{}
	remaining := string(contents)
	number := 0
	for len(remaining) > 0 {
		text, ending, rest := splitLine(remaining)
		number++
		line := Line{Number: number, Raw: text, Ending: ending}
		trimmed := strings.TrimSpace(text)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			entry, err := parseEntry(trimmed)
			if err != nil {
				line.Problem = err.Error()
			} else {
				line.Entry = entry
			}
		}
		file.Lines = append(file.Lines, line)
		remaining = rest
	}
	return file
}

// Render は、読み込んだときとまったく同じファイルを返す。
func (f *File) Render() []byte {
	var builder strings.Builder
	for _, line := range f.Lines {
		builder.WriteString(line.Raw)
		builder.WriteString(line.Ending)
	}
	return []byte(builder.String())
}

// Entries は、解析済みレコードを持つ行だけを返す。
func (f *File) Entries() []Line {
	var entries []Line
	for _, line := range f.Lines {
		if line.Entry != nil {
			entries = append(entries, line)
		}
	}
	return entries
}

func splitLine(text string) (content, ending, rest string) {
	index := strings.IndexByte(text, '\n')
	if index < 0 {
		return text, "", ""
	}
	content, ending, rest = text[:index], "\n", text[index+1:]
	if strings.HasSuffix(content, "\r") {
		content, ending = content[:len(content)-1], "\r\n"
	}
	return content, ending, rest
}

func parseEntry(text string) (*Entry, error) {
	fields := strings.Fields(text)
	entry := &Entry{}
	if len(fields) > 0 && strings.HasPrefix(fields[0], "@") {
		entry.Marker = fields[0]
		fields = fields[1:]
	}
	if len(fields) < 3 {
		return nil, errors.New("line does not have a host, key type and key")
	}

	entry.Hosts = strings.Split(fields[0], ",")
	entry.Hashed = strings.HasPrefix(fields[0], "|1|")
	entry.KeyType = fields[1]
	entry.Key = fields[2]
	entry.Comment = strings.Join(fields[3:], " ")

	fingerprint, err := Fingerprint(entry.Key)
	if err != nil {
		return nil, err
	}
	entry.Fingerprint = fingerprint
	return entry, nil
}

// Fingerprint は、OpenSSH が公開鍵に対して表示する SHA256 フィンガープリントを返す。
func Fingerprint(encodedKey string) (string, error) {
	blob, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil || len(blob) == 0 {
		return "", ErrInvalidKey
	}
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

// MatchesHost は、このエントリが host を対象にしているかを報告する。
//
// ハッシュ化されたエントリは読み戻せないが、検査はできる。OpenSSH は
// |1|base64(salt)|base64(HMAC-SHA1(salt, host)) を保存するので、同じ計算をすれば
// 何も明かさずに問いに答えられる。
func (e *Entry) MatchesHost(host string) bool {
	for _, pattern := range e.Hosts {
		if e.Hashed {
			if hashedMatch(pattern, host) {
				return true
			}
			continue
		}
		if matchHostPattern(pattern, host) {
			return true
		}
	}
	return false
}

func hashedMatch(field, host string) bool {
	parts := strings.Split(field, "|")
	if len(parts) != 4 || parts[1] != "1" {
		return false
	}
	salt, saltErr := base64.StdEncoding.DecodeString(parts[2])
	expected, hashErr := base64.StdEncoding.DecodeString(parts[3])
	if saltErr != nil || hashErr != nil {
		return false
	}
	mac := hmac.New(sha1.New, salt)
	mac.Write([]byte(host))
	return hmac.Equal(mac.Sum(nil), expected)
}

// matchHostPattern は、known_hosts のパターンで OpenSSH が使う '*' と '?' の
// マッチングを、大文字小文字を区別せずに実装する。
func matchHostPattern(pattern, host string) bool {
	loweredPattern := strings.ToLower(pattern)
	loweredHost := strings.ToLower(host)

	patternIndex, hostIndex := 0, 0
	starIndex, resumeIndex := -1, 0
	for hostIndex < len(loweredHost) {
		switch {
		case patternIndex < len(loweredPattern) &&
			(loweredPattern[patternIndex] == '?' || loweredPattern[patternIndex] == loweredHost[hostIndex]):
			patternIndex++
			hostIndex++
		case patternIndex < len(loweredPattern) && loweredPattern[patternIndex] == '*':
			starIndex = patternIndex
			resumeIndex = hostIndex
			patternIndex++
		case starIndex >= 0:
			patternIndex = starIndex + 1
			resumeIndex++
			hostIndex = resumeIndex
		default:
			return false
		}
	}
	for patternIndex < len(loweredPattern) && loweredPattern[patternIndex] == '*' {
		patternIndex++
	}
	return patternIndex == len(loweredPattern)
}

// Search は、ホスト・鍵種別・フィンガープリント・コメントのいずれかに query を
// 含むエントリを返す。query が空ならすべてのエントリを返す。
func Search(file *File, query string) []Line {
	wanted := strings.ToLower(strings.TrimSpace(query))
	var found []Line
	for _, line := range file.Entries() {
		if wanted == "" {
			found = append(found, line)
			continue
		}
		haystack := strings.ToLower(strings.Join(line.Entry.Hosts, ",") + " " +
			line.Entry.KeyType + " " + line.Entry.Fingerprint + " " + line.Entry.Comment)
		if strings.Contains(haystack, wanted) {
			found = append(found, line)
		}
	}
	return found
}
