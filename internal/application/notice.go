package application

// Notice explains something the UI must show instead of inventing an answer.
// Diagnostics come from the configuration engine and describe file structure;
// notices come from this package and describe why a projection is incomplete.
type Notice struct {
	Code   string `json:"code"`
	Path   string `json:"path,omitempty"`
	Line   int    `json:"line,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Notice codes are stable identifiers the UI maps to its own copy.
const (
	// NoticeComplexExternalRule marks a host whose value cannot be projected
	// into a simple inheritance model. The UI shows the real source instead.
	NoticeComplexExternalRule = "complex_external_rule"
	NoticeDuplicateAlias      = "duplicate_alias"
	NoticeWildcardShadow      = "wildcard_shadow"
	NoticeNegatedPattern      = "negated_pattern"
	NoticeUnnamedHostBlock    = "unnamed_host_block"
	NoticeMatchBlock          = "match_block"
	NoticeDangerousDirective  = "dangerous_directive"
	NoticeUnstructuredLine    = "unstructured_line"
	NoticeExternalFile        = "external_file"
	NoticeOrphanMetadata      = "orphan_metadata"
	NoticeGroupCycle          = "group_cycle"
	NoticeGroupMemberMissing  = "group_member_missing"
	NoticeExplainedValuesOnly = "explained_values_only"
	// NoticeDestinationNotIncluded marks a destination file that no Include
	// reaches, so a block moved into it would stop being read by OpenSSH.
	NoticeDestinationNotIncluded = "destination_not_included"
)

// appendNotice adds a notice unless the identical notice is already present.
func appendNotice(notices []Notice, notice Notice) []Notice {
	for _, existing := range notices {
		if existing == notice {
			return notices
		}
	}
	return append(notices, notice)
}
