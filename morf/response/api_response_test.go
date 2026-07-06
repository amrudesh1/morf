/*
Copyright [2023] [Amrudesh Balakrishnan]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package response

import (
	"morf/models"
	"testing"
)

// TestCreateBasicResponse guards the envelope shape the UI/spec depend on
// (A-1): fileName passthrough, secretCount = len(scannerData), and a secrets key.
func TestCreateBasicResponse(t *testing.T) {
	scanner := []models.SecretModel{{}, {}, {}}
	h := NewAPIResponseHandler(models.Secrets{FileName: "app.apk"}, scanner)
	resp := h.CreateBasicResponse()

	if resp["fileName"] != "app.apk" {
		t.Errorf("fileName = %v, want app.apk", resp["fileName"])
	}
	if resp["secretCount"] != len(scanner) {
		t.Errorf("secretCount = %v, want %d", resp["secretCount"], len(scanner))
	}
	if _, ok := resp["secrets"]; !ok {
		t.Error("basic response is missing the secrets key")
	}
}

// TestSuccessAndDuplicateEnvelopes pins the standardized envelopes used by both
// the synchronous and worker result paths (A-1).
func TestSuccessAndDuplicateEnvelopes(t *testing.T) {
	h := NewAPIResponseHandler(models.Secrets{FileName: "x.apk"}, nil)

	s := h.CreateSuccessResponse()
	if s["message"] != "Success" {
		t.Errorf("success message = %v, want Success", s["message"])
	}
	if _, ok := s["data"]; !ok {
		t.Error("success envelope missing data")
	}

	d := h.CreateDuplicateResponse()
	if d["message"] != "Item already exists" {
		t.Errorf("duplicate message = %v, want 'Item already exists'", d["message"])
	}
	if _, ok := d["data"]; !ok {
		t.Error("duplicate envelope missing data")
	}
}

func TestParseExistingSecretRoundTrip(t *testing.T) {
	got, err := ParseExistingSecret(`{"fileName":"sample.apk","apkHash":"abc123"}`)
	if err != nil {
		t.Fatalf("ParseExistingSecret error: %v", err)
	}
	if got.FileName != "sample.apk" || got.APKHash != "abc123" {
		t.Errorf("parsed = {FileName:%q APKHash:%q}, want {sample.apk abc123}", got.FileName, got.APKHash)
	}
}

func TestParseExistingSecretInvalidJSON(t *testing.T) {
	if _, err := ParseExistingSecret("{not valid json"); err == nil {
		t.Error("expected an error for invalid JSON, got nil")
	}
}
