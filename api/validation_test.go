package api

import "testing"

func TestValidateHash(t *testing.T) {
	tests := []struct {
		name    string
		hash    string
		wantErr bool
	}{
		{"valid sha256", "d41d8cd98f00b204e9800998ecf8427e00000000000000000000000000000000", false},
		{"valid md5", "d41d8cd98f00b204e9800998ecf8427e", false},
		{"empty", "", true},
		{"too short", "a", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateHash(tt.hash); (err != nil) != tt.wantErr {
				t.Errorf("ValidateHash() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateTag(t *testing.T) {
	tests := []struct {
		name    string
		tag     string
		wantErr bool
	}{
		{"valid", "Emotet", false},
		{"empty", "", true},
		{"too short", "a", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateTag(tt.tag); (err != nil) != tt.wantErr {
				t.Errorf("ValidateTag() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAdditionalInputValidators(t *testing.T) {
	if err := ValidateSHA256("d41d8cd98f00b204e9800998ecf8427e00000000000000000000000000000000"); err != nil {
		t.Errorf("valid SHA256 rejected: %v", err)
	}
	if err := ValidateMD5("d41d8cd98f00b204e9800998ecf8427e"); err != nil {
		t.Errorf("valid MD5 rejected: %v", err)
	}
	if err := ValidateMalware(""); err == nil {
		t.Error("empty malware accepted")
	}
	if err := ValidateMalware(string(make([]byte, 101))); err == nil {
		t.Error("long malware accepted")
	}
	if err := ValidateIOCID(0); err == nil {
		t.Error("zero IOC ID accepted")
	}
	if err := ValidateSearchTerm(""); err == nil {
		t.Error("empty search term accepted")
	}
	if err := ValidateLimit(-1); err == nil {
		t.Error("negative limit accepted")
	}
	if err := ValidateLimit(1001); err == nil {
		t.Error("oversized limit accepted")
	}
}
