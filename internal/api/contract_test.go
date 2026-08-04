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
