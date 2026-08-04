package api

import "testing"

func TestGeneratedFoundationModels(t *testing.T) {
	health := HealthResponse{Status: "ok", Version: "dev"}
	if health.Status != "ok" || health.Version != "dev" {
		t.Fatalf("unexpected health response: %#v", health)
	}
	bootstrap := BootstrapResponse{CsrfToken: "csrf"}
	if bootstrap.CsrfToken != "csrf" {
		t.Fatalf("unexpected bootstrap response: %#v", bootstrap)
	}
}

func TestGeneratedKeyVaultModels(t *testing.T) {
	item := KeyItem{
		Id:             "0123456789abcdef0123456789abcdef",
		RelativePath:   "id_work",
		Kind:           "private_key",
		Container:      "OPENSSH PRIVATE KEY",
		Algorithm:      "ed25519",
		KeyType:        "ssh-ed25519",
		Bits:           256,
		Encrypted:      true,
		Fingerprint:    "SHA256:abcdef",
		Comment:        "aida@laptop",
		Permission:     "0600",
		PermissionRisk: false,
		SizeBytes:      444,
		References: []KeyReference{{
			Directive:    "IdentityFile",
			ConfigPath:   "/Users/example/.ssh/config",
			Line:         2,
			Condition:    "Host build-*",
			HostPatterns: []string{"build-*"},
			Value:        "~/.ssh/id_work",
		}},
		Notes: []string{},
	}
	if item.Bits != 256 || item.References[0].Directive != "IdentityFile" {
		t.Fatalf("unexpected key item: %#v", item)
	}
	if item.Certificate != nil {
		t.Fatalf("certificate must be optional and absent by default")
	}

	inventory := KeyInventoryResponse{
		Items:                []KeyItem{item},
		Unreadable:           []UnreadableFile{{RelativePath: "huge_known_hosts", Reason: "file_too_large"}},
		AgentDelegations:     []KeyReference{},
		UnresolvedReferences: []UnresolvedReference{},
		AgentAvailable:       true,
		AgentIdentities:      []AgentIdentity{{Bits: 256, Fingerprint: "SHA256:abcdef", Comment: "aida@laptop", Algorithm: "ED25519"}},
	}
	if len(inventory.Items) != 1 || !inventory.AgentAvailable {
		t.Fatalf("unexpected inventory: %#v", inventory)
	}

	certificate := KeyCertificate{
		KeyId:                "probe-id",
		Principals:           []string{"alice"},
		ValidBefore:          0,
		NeverExpires:         true,
		SignedKeyType:        "ssh-ed25519",
		SignedKeyFingerprint: "SHA256:abcdef",
	}
	if !certificate.NeverExpires || certificate.ValidBefore != 0 {
		t.Fatalf("unexpected certificate: %#v", certificate)
	}

	reveal := RevealPrivateKeyResponse{
		Id:            item.Id,
		RelativePath:  "id_work",
		PrivateKey:    "-----BEGIN OPENSSH PRIVATE KEY-----\n",
		Encrypted:     true,
		Fingerprint:   "SHA256:abcdef",
		TransactionId: "20260805T090000.000-aabbccdd",
	}
	if reveal.TransactionId == "" {
		t.Fatalf("unexpected reveal response: %#v", reveal)
	}

	// The request names the committed session vocabulary: a kind and a target.
	// Evidence is never supplied by the caller; the server derives it from what
	// the confirmation dialog was showing.
	request := IssueActionRequest{Kind: "private_key.reveal", Target: item.Id}
	action := IssueActionResponse{Token: "t", ExpiresAt: "2026-08-05T09:02:00Z"}
	if request.Kind != "private_key.reveal" || action.ExpiresAt == "" {
		t.Fatalf("unexpected action contract: %#v %#v", request, action)
	}

	trash := TrashListResponse{
		Entries: []TrashEntrySummary{{
			Id:         "20260805T090000.000-aabbccdd",
			DeletedAt:  "2026-08-05T09:00:00Z",
			AgeDays:    40,
			Stale:      true,
			Files:      []TrashFileSummary{{OriginalRelativePath: "id_work", TrashRelativePath: "ssh-ui/trash/e/id_work", Kind: "private_key", Fingerprint: "SHA256:abcdef", Permission: "0600"}},
			Restorable: false,
			Blockers:   []string{"restore_path_occupied:id_work"},
		}},
		RetentionDays: 30,
	}
	if trash.RetentionDays != 30 || !trash.Entries[0].Stale {
		t.Fatalf("unexpected trash response: %#v", trash)
	}

	algorithms := KeyAlgorithmsResponse{
		Variants:   []KeyVariant{{Algorithm: "ed25519-sk", Bits: 0, Label: "Ed25519 security key", InProcess: false, Reason: "hardware_token_required"}},
		Source:     "ssh -Q key",
		Diagnostic: "",
	}
	generate := GenerateKeyResponse{
		Id: item.Id, RelativePath: "id_work", PublicRelativePath: "id_work.pub",
		Fingerprint: "SHA256:abcdef", KeyType: "ssh-ed25519", Bits: 256,
		Encrypted: true, TransactionId: "20260805T090000.000-aabbccdd",
	}
	hardware := HardwareCommandResponse{
		Algorithm: "ed25519-sk",
		Command:   []string{"ssh-keygen", "-t", "ed25519-sk"},
		Note:      "run this in Terminal",
	}
	if algorithms.Variants[0].InProcess || generate.PublicRelativePath == "" || len(hardware.Command) != 3 {
		t.Fatalf("unexpected generation contract: %#v %#v %#v", algorithms, generate, hardware)
	}

	passphrase := ChangePassphraseResponse{
		Id: item.Id, RelativePath: "id_work", Encrypted: true,
		Notes: []string{}, TransactionId: "20260805T090000.000-aabbccdd",
	}
	register := RegisterKeyResponse{
		Id: item.Id, RelativePath: "id_work", Fingerprint: "SHA256:abcdef",
		LifetimeSeconds: 3600, StoredInKeychain: true, Identities: []AgentIdentity{},
	}
	trashed := TrashKeyResponse{EntryId: "e", Files: []TrashFileSummary{}, Skipped: []string{}, TransactionId: "t"}
	restored := RestoreTrashResponse{EntryId: "e", Restored: []string{"id_work"}, Blockers: []string{}, TransactionId: "t"}
	purged := PurgeTrashResponse{EntryId: "e", Removed: []string{"id_work"}, TransactionId: "t"}
	if !passphrase.Encrypted || !register.StoredInKeychain || trashed.EntryId == "" ||
		len(restored.Restored) != 1 || len(purged.Removed) != 1 {
		t.Fatalf("unexpected key vault responses")
	}

	problem := Problem{Code: "agent_rejected", Message: "request rejected", Detail: stringPointer("Bad passphrase for ~/.ssh/id_work")}
	if problem.Detail == nil || *problem.Detail == "" {
		t.Fatalf("Problem carries no detail field")
	}
}

func stringPointer(value string) *string { return &value }
