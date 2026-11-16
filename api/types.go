package api

import (
	"bytes"
	"encoding/json"
)

// IOCResponse represents a standard ThreatFox API response with IOC data
type IOCResponse struct {
	QueryStatus string     `json:"query_status"`
	QueryInfo   *QueryInfo `json:"query_info,omitempty"`
	Data        []IOC      `json:"data,omitempty"`
}

// QueryInfo describes the search the API actually ran. result_count comes back
// as a number and result_max as a string, so both are json.Number.
type QueryInfo struct {
	SearchScope string      `json:"search_scope,omitempty"`
	ResultCount json.Number `json:"result_count,omitempty"`
	ResultMax   json.Number `json:"result_max,omitempty"`
}

// SingleIOCResponse represents a response for a single IOC query
type SingleIOCResponse struct {
	// The ioc query answers with a bare object and no query_status.
	QueryStatus     string          `json:"query_status,omitempty"`
	ID              string          `json:"id,omitempty"`
	IOC             string          `json:"ioc,omitempty"`
	ThreatType      string          `json:"threat_type,omitempty"`
	ThreatTypeDesc  string          `json:"threat_type_desc,omitempty"`
	IOCType         string          `json:"ioc_type,omitempty"`
	IOCTypeDesc     string          `json:"ioc_type_desc,omitempty"`
	Malware         string          `json:"malware,omitempty"`
	MalwarePrint    string          `json:"malware_printable,omitempty"`
	MalwareAlias    *string         `json:"malware_alias,omitempty"`
	MalwareMalpedia string          `json:"malware_malpedia,omitempty"`
	ConfidenceLevel int             `json:"confidence_level,omitempty"`
	FirstSeen       string          `json:"first_seen,omitempty"`
	LastSeen        *string         `json:"last_seen,omitempty"`
	Reference       *string         `json:"reference,omitempty"`
	Reporter        string          `json:"reporter,omitempty"`
	IsCompromised   bool            `json:"is_compromised"`
	Sightings       json.Number     `json:"sightings,omitempty"`
	Comment         string          `json:"comment,omitempty"`
	Tags            []string        `json:"tags,omitempty"`
	Credits         []Credit        `json:"credits,omitempty"`
	MalwareSamples  []MalwareSample `json:"malware_samples,omitempty"`
}

// IOC represents an indicator of compromise from ThreatFox
type IOC struct {
	ID              string          `json:"id"`
	IOC             string          `json:"ioc"`
	ThreatType      string          `json:"threat_type"`
	ThreatTypeDesc  string          `json:"threat_type_desc"`
	IOCType         string          `json:"ioc_type"`
	IOCTypeDesc     string          `json:"ioc_type_desc"`
	Malware         string          `json:"malware"`
	MalwarePrint    string          `json:"malware_printable"`
	MalwareAlias    *string         `json:"malware_alias"`
	MalwareMalpedia string          `json:"malware_malpedia"`
	ConfidenceLevel int             `json:"confidence_level"`
	FirstSeen       string          `json:"first_seen"`
	LastSeen        *string         `json:"last_seen"`
	Reference       *string         `json:"reference"`
	Reporter        string          `json:"reporter"`
	IsCompromised   bool            `json:"is_compromised"`
	Tags            []string        `json:"tags"`
	MalwareSamples  []MalwareSample `json:"malware_samples,omitempty"`
}

// MalwareSample represents a malware sample associated with an IOC
type MalwareSample struct {
	TimeStamp     string `json:"time_stamp"`
	MD5Hash       string `json:"md5_hash"`
	SHA256Hash    string `json:"sha256_hash"`
	MalwareBazaar string `json:"malware_bazaar"`
}

// Credit represents credits for an IOC submission
// CreditsAmount arrives quoted, so json.Number accepts both forms.
type Credit struct {
	CreditsFrom   string      `json:"credits_from"`
	CreditsAmount json.Number `json:"credits_amount"`
}

// MalwareListResponse represents the response from malware_list query
type MalwareListResponse struct {
	QueryStatus string                    `json:"query_status"`
	Data        map[string]MalwareDetails `json:"data,omitempty"`
}

// MalwareDetails represents details about a malware family
type MalwareDetails struct {
	MalwarePrintable string  `json:"malware_printable"`
	MalwareAlias     *string `json:"malware_alias"`
}

// TypesResponse represents the response from types query
type TypesResponse struct {
	QueryStatus string             `json:"query_status"`
	Data        map[string]IOCType `json:"data,omitempty"`
}

// IOCType represents an IOC/threat type
type IOCType struct {
	IOCType     string `json:"ioc_type"`
	ThreatType  string `json:"fk_threat_type"`
	Description string `json:"description"`
}

// TagListResponse represents the response from tag_list query
type TagListResponse struct {
	QueryStatus string             `json:"query_status"`
	Data        map[string]TagInfo `json:"data,omitempty"`
}

// TagInfo represents information about a tag
type TagInfo struct {
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	Color     string `json:"color"`
}

// LabelResponse represents the response from get_label query
type LabelResponse struct {
	QueryStatus string        `json:"query_status"`
	Data        []LabelResult `json:"data,omitempty"`
}

// LabelResult represents a malware label lookup result
type LabelResult struct {
	Malware          string  `json:"malware"`
	MalwarePrintable string  `json:"malware_printable"`
	MalwareAlias     *string `json:"malware_alias"`
}

// SubmitResponse represents the response from submit_ioc query
// The shape of data is not published, so it is kept raw and printed as the
// API sent it rather than being squeezed into a guess.
type SubmitResponse struct {
	QueryStatus string          `json:"query_status"`
	Data        json.RawMessage `json:"data,omitempty"`
}

// ParseIOCResponse parses the raw JSON response into an IOCResponse struct.
// The API sends data as an array on success and as a string on errors. Decode
// once, and only decode data when it is an array.
func ParseIOCResponse(data []byte) (*IOCResponse, error) {
	var envelope struct {
		QueryStatus json.RawMessage `json:"query_status"`
		QueryInfo   *QueryInfo      `json:"query_info,omitempty"`
		Data        json.RawMessage `json:"data,omitempty"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, err
	}

	resp := &IOCResponse{QueryInfo: envelope.QueryInfo}
	if len(envelope.QueryStatus) > 0 && string(envelope.QueryStatus) != "null" {
		if err := json.Unmarshal(envelope.QueryStatus, &resp.QueryStatus); err != nil {
			resp.QueryStatus = string(envelope.QueryStatus)
		}
	}

	rawData := bytes.TrimSpace(envelope.Data)
	if len(rawData) > 0 && rawData[0] == '[' {
		if err := json.Unmarshal(rawData, &resp.Data); err != nil {
			return nil, err
		}
	}

	return resp, nil
}

// ParseSingleIOCResponse parses the raw JSON response into a SingleIOCResponse struct
func ParseSingleIOCResponse(data []byte) (*SingleIOCResponse, error) {
	var resp SingleIOCResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ParseMalwareListResponse parses the raw JSON response
func ParseMalwareListResponse(data []byte) (*MalwareListResponse, error) {
	var resp MalwareListResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ParseTypesResponse parses the raw JSON response
func ParseTypesResponse(data []byte) (*TypesResponse, error) {
	var resp TypesResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ParseTagListResponse parses the raw JSON response
func ParseTagListResponse(data []byte) (*TagListResponse, error) {
	var resp TagListResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ParseLabelResponse parses the raw JSON response
func ParseLabelResponse(data []byte) (*LabelResponse, error) {
	var resp LabelResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ParseSubmitResponse parses the raw JSON response
func ParseSubmitResponse(data []byte) (*SubmitResponse, error) {
	var resp SubmitResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
