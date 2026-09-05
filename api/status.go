package api

import (
	"encoding/json"
	"fmt"
)

// StatusError is returned when the API answers with a query_status other than
// "ok". ThreatFox usually puts a human readable explanation in the data field
// of an error response, which is preferred over anything hardcoded here.
type StatusError struct {
	Status string
	Detail string
	Query  string
}

func (e *StatusError) Error() string {
	if e.Detail != "" {
		return e.Detail
	}
	if msg, ok := statusMessages[e.Status]; ok {
		return msg
	}
	if e.Query != "" {
		return fmt.Sprintf("the API rejected the %s query with status %q", e.Query, e.Status)
	}
	return fmt.Sprintf("the API returned status %q", e.Status)
}

// CheckStatus inspects a raw API response and returns a *StatusError when the
// query did not succeed. A response with no query_status at all is treated as
// success: the "ioc" query answers with a bare IOC object.
func CheckStatus(raw []byte, query string) error {
	var probe struct {
		QueryStatus string          `json:"query_status"`
		Data        json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil // let the caller's own decoding report the problem
	}
	if probe.QueryStatus == "" || probe.QueryStatus == "ok" {
		return nil
	}

	// On failure the data field carries a sentence explaining what went wrong.
	var detail string
	if len(probe.Data) > 0 {
		_ = json.Unmarshal(probe.Data, &detail)
	}

	return &StatusError{Status: probe.QueryStatus, Detail: detail, Query: query}
}

// statusMessages is a fallback for statuses the API reports without an
// explanation. These were observed against the live API; the published
// documentation does not enumerate its error statuses.
var statusMessages = map[string]string{
	"no_result":           "the query returned no results",
	"unknown_operation":   "the API does not recognise that query type",
	"illegal_search_term": "the API rejected that search term",
	"illegal_ioc_id":      "the API rejected that IOC id",
	"unknown_ioc_id":      "that IOC id is unknown to ThreatFox",
	"illegal_days":        "days must be a number between 1 and 7",
	"illegal_hash":        "the hash must be an MD5 or SHA256 hash",
	// The API misspells this one.
	"illegl_hash":        "the hash must be an MD5 or SHA256 hash",
	"illegal_tag":        "the API rejected that tag",
	"illegal_malware":    "the API rejected that malware name",
	"no_api_key":         "no API key was accepted: set ABUSECH_API_KEY (get one at https://auth.abuse.ch/)",
	"user_blacklisted":   "this API key is blacklisted: contact https://www.spamhaus.com/#contact-form",
	"http_post_expected": "the API expected an HTTP POST request",
}
