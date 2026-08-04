package httpserver

import (
	"errors"
	"strings"
	"testing"

	"ssh-ui/internal/application"
)

func TestValidatePathParameterRejectsTraversalAndControlCharacters(t *testing.T) {
	for _, valid := range []string{"config", "conf.d/10-home.conf", "a..b.conf"} {
		if err := validatePathParameter(valid); err != nil {
			t.Errorf("validatePathParameter(%q) = %v, want nil", valid, err)
		}
	}
	for _, invalid := range []string{"", "/etc/ssh/ssh_config", "../.bashrc", "conf.d/../../escape", "conf.d/./x", "a\x00b", "a\nb", strings.Repeat("a", 600)} {
		if err := validatePathParameter(invalid); !errors.Is(err, errInvalidPath) {
			t.Errorf("validatePathParameter(%q) = %v, want errInvalidPath", invalid, err)
		}
	}
}

func TestValidateEditRequestEnforcesEveryKindsRequirements(t *testing.T) {
	tests := []struct {
		name    string
		request application.EditRequest
		wantErr bool
	}{
		{"valid field edit", application.EditRequest{
			Kind: application.EditHostFields, Path: "config", Base: "Host a\n", Alias: "a",
			Fields: []application.FieldEdit{{Action: application.ActionSet, Line: 2, Values: []string{"22"}}},
		}, false},
		{"unknown kind", application.EditRequest{Kind: "delete_everything", Path: "config"}, true},
		{"field edit without an alias", application.EditRequest{
			Kind: application.EditHostFields, Path: "config", Base: "Host a\n",
			Fields: []application.FieldEdit{{Action: application.ActionSet, Line: 2}},
		}, true},
		{"field edit without any edit", application.EditRequest{
			Kind: application.EditHostFields, Path: "config", Base: "Host a\n", Alias: "a",
		}, true},
		{"unknown field action", application.EditRequest{
			Kind: application.EditHostFields, Path: "config", Base: "Host a\n", Alias: "a",
			Fields: []application.FieldEdit{{Action: "wipe", Line: 2}},
		}, true},
		{"oversized value", application.EditRequest{
			Kind: application.EditHostFields, Path: "config", Base: "Host a\n", Alias: "a",
			Fields: []application.FieldEdit{{Action: application.ActionSet, Line: 2, Values: []string{strings.Repeat("v", maxValueLength+1)}}},
		}, true},
		{"rename with a pattern alias", application.EditRequest{
			Kind: application.EditRename, Path: "config", Base: "Host a\n", Alias: "a", NewAlias: "b*",
		}, true},
		{"valid rename", application.EditRequest{
			Kind: application.EditRename, Path: "config", Base: "Host a\n", Alias: "a", NewAlias: "b",
		}, false},
		{"raw edit without a path", application.EditRequest{Kind: application.EditFileRaw, Raw: "Host a\n"}, true},
		{"emptying a file is allowed", application.EditRequest{
			Kind: application.EditFileRaw, Path: "config", Base: "Host a\n", Raw: "",
		}, false},
		{"groups without metadata", application.EditRequest{Kind: application.EditGroups}, true},
		{"metadata with key material", application.EditRequest{
			Kind: application.EditMetadata,
			Metadata: &application.Metadata{
				SchemaVersion: application.MetadataSchemaVersion,
				GroupsFile:    application.DefaultGroupsFile,
				Hosts: []application.HostMetadata{{
					Identity: application.HostIdentity{Path: "config", Alias: "a"},
					Note:     "-----BEGIN OPENSSH PRIVATE KEY-----",
				}},
			},
		}, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateEditRequest(test.request)
			if test.wantErr != (err != nil) {
				t.Fatalf("validateEditRequest = %v, wantErr = %v", err, test.wantErr)
			}
		})
	}
}
