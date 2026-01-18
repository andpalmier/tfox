package api

import (
	"encoding/json"
	"fmt"
)

// IOCResponse represents a standard ThreatFox API response with IOC data
type IOCResponse struct {
	QueryStatus string `json:"query_status"`
	Data        []IOC  `json:"data,omitempty"`
}

// SingleIOCResponse represents a response for a single IOC query
type SingleIOCResponse struct {
	QueryStatus     string          `json:"query_status"`
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
type Credit struct {
	CreditsFrom   string `json:"credits_from"`
	CreditsAmount int    `json:"credits_amount"`
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
type SubmitResponse struct {
	QueryStatus string `json:"query_status"`
	Data        struct {
		OK      int `json:"ok,omitempty"`
		Ignored int `json:"ignored,omitempty"`
	} `json:"data,omitempty"`
}

// ParseIOCResponse parses the raw JSON response into an IOCResponse struct
func ParseIOCResponse(data []byte) (*IOCResponse, error) {
	// First unmarshal into a map to check the structure of 'data'
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	resp := &IOCResponse{
		QueryStatus: fmt.Sprintf("%v", raw["query_status"]),
	}

	// Check if 'data' is an array
	if dataVal, ok := raw["data"]; ok {
		switch v := dataVal.(type) {
		case []interface{}:
			// Re-marshal and unmarshal into the specific type
			dataJSON, err := json.Marshal(v)
			if err != nil {
				return nil, err
			}
			if err := json.Unmarshal(dataJSON, &resp.Data); err != nil {
				return nil, err
			}
		case string:
			// If it's a string and the status is not 'ok', we treat it as no results
			// and keep resp.Data empty
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
