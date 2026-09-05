package api

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The files under testdata are real responses captured from the live
// ThreatFox API. Decoding them with DisallowUnknownFields means a field the
// API returns but the structs do not model fails the tests, which is how
// is_compromised and query_info went missing before.
func TestLiveResponsesDecodeCompletely(t *testing.T) {
	tests := []struct {
		file string
		into func() any
	}{
		{"get_iocs.json", func() any { return &IOCResponse{} }},
		{"taginfo.json", func() any { return &IOCResponse{} }},
		{"malwareinfo.json", func() any { return &IOCResponse{} }},
		{"ioc.json", func() any { return &SingleIOCResponse{} }},
		{"malware_list.json", func() any { return &MalwareListResponse{} }},
		{"types.json", func() any { return &TypesResponse{} }},
		{"tag_list.json", func() any { return &TagListResponse{} }},
		{"get_label.json", func() any { return &LabelResponse{} }},
	}

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join("testdata", tt.file))
			if err != nil {
				t.Fatal(err)
			}
			dec := json.NewDecoder(bytes.NewReader(b))
			dec.DisallowUnknownFields()
			if err := dec.Decode(tt.into()); err != nil {
				t.Errorf("live response does not fit the structs: %v", err)
			}
		})
	}
}

// query_info tells the caller what the API actually searched. It used to be
// discarded by the hand-rolled parser.
func TestQueryInfoSurvivesParsing(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "malwareinfo.json"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := ParseIOCResponse(b)
	if err != nil {
		t.Fatal(err)
	}
	if resp.QueryInfo == nil {
		t.Fatal("query_info was dropped")
	}
	if resp.QueryInfo.SearchScope == "" {
		t.Error("query_info.search_scope is empty")
	}
	// result_count is a number and result_max a string; both must survive.
	if resp.QueryInfo.ResultCount.String() == "" {
		t.Error("query_info.result_count is empty")
	}
	if resp.QueryInfo.ResultMax.String() == "" {
		t.Error("query_info.result_max is empty")
	}
}

// On failure the API puts a sentence in data explaining what went wrong.
// That sentence is the error the user should see.
func TestCheckStatusPrefersAPIExplanation(t *testing.T) {
	raw := []byte(`{"query_status":"illegal_search_term","data":"The search_term you have provided is not valid"}`)
	err := CheckStatus(raw, "search_ioc")
	if err == nil {
		t.Fatal("expected an error")
	}
	if err.Error() != "The search_term you have provided is not valid" {
		t.Errorf("got %q, want the API's own explanation", err.Error())
	}

	var se *StatusError
	if !errorsAs(err, &se) || se.Status != "illegal_search_term" {
		t.Errorf("raw status should stay available for matching, got %+v", err)
	}
}

// Without an explanation the fallback table is used.
func TestCheckStatusFallsBackToTable(t *testing.T) {
	err := CheckStatus([]byte(`{"query_status":"no_result"}`), "taginfo")
	if err == nil || err.Error() != "the query returned no results" {
		t.Errorf("got %v, want the fallback message", err)
	}
}

// A response with no query_status at all is a success: the ioc query answers
// with a bare IOC object.
func TestCheckStatusAllowsBareObject(t *testing.T) {
	if err := CheckStatus([]byte(`{"id":"1901292","ioc":"evil.example"}`), "ioc"); err != nil {
		t.Errorf("bare object should be accepted, got %v", err)
	}
}

func errorsAs(err error, target **StatusError) bool {
	se, ok := err.(*StatusError)
	if ok {
		*target = se
	}
	return ok
}
