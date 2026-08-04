package platform

import "strings"

// SanitiseHomePaths rewrites the user's home directory to "~" in text.
//
// Verbose OpenSSH output names every file it read by absolute path, so the
// captured stderr of a connection attempt would otherwise carry the account
// name of the person running this application into a response body. The text
// is still shown, because the user needs it to understand a failure; only the
// part that identifies their account is removed.
//
// An empty or root home is ignored: rewriting "/" would mangle every absolute
// path in the output without hiding anything.
func SanitiseHomePaths(text, home string) string {
	cleaned := strings.TrimRight(home, "/")
	if cleaned == "" {
		return text
	}
	return strings.ReplaceAll(text, cleaned, "~")
}
