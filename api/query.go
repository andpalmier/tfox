package api

import (
	"context"
	"fmt"
)

// GetRecentIOCs retrieves recent IOCs from ThreatFox
func (c *Client) GetRecentIOCs(ctx context.Context, days int) ([]IOC, error) {
	if days > 0 {
		if err := ValidateDays(days); err != nil {
			return nil, err
		}
	} else {
		days = 3 // Default
	}

	payload := map[string]interface{}{
		"query": "get_iocs",
		"days":  days,
	}

	response, err := c.MakeRequest(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("error retrieving recent IOCs: %w", err)
	}

	resp, err := ParseIOCResponse([]byte(response))
	if err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	if resp.QueryStatus != "ok" {
		return nil, fmt.Errorf("API returned status: %s", resp.QueryStatus)
	}

	return resp.Data, nil
}

// GetIOCByID retrieves an IOC by its ID
func (c *Client) GetIOCByID(ctx context.Context, id int) (*SingleIOCResponse, error) {
	if err := ValidateIOCID(id); err != nil {
		return nil, err
	}

	payload := map[string]interface{}{
		"query": "ioc",
		"id":    id,
	}

	response, err := c.MakeRequest(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("error retrieving IOC: %w", err)
	}

	resp, err := ParseSingleIOCResponse([]byte(response))
	if err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	if resp.QueryStatus != "ok" {
		return nil, fmt.Errorf("API returned status: %s", resp.QueryStatus)
	}

	return resp, nil
}

// SearchIOC searches for an IOC on ThreatFox
func (c *Client) SearchIOC(ctx context.Context, searchTerm string, exactMatch bool) ([]IOC, error) {
	if err := ValidateSearchTerm(searchTerm); err != nil {
		return nil, err
	}

	payload := map[string]interface{}{
		"query":       "search_ioc",
		"search_term": searchTerm,
	}

	if exactMatch {
		payload["exact_match"] = true
	}

	response, err := c.MakeRequest(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("error searching IOC: %w", err)
	}

	resp, err := ParseIOCResponse([]byte(response))
	if err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	if resp.QueryStatus != "ok" {
		return nil, fmt.Errorf("API returned status: %s", resp.QueryStatus)
	}

	return resp.Data, nil
}

// SearchByHash searches for IOCs associated with a file hash
func (c *Client) SearchByHash(ctx context.Context, hash string) ([]IOC, error) {
	if err := ValidateHash(hash); err != nil {
		return nil, err
	}

	payload := map[string]interface{}{
		"query": "search_hash",
		"hash":  hash,
	}

	response, err := c.MakeRequest(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("error searching by hash: %w", err)
	}

	resp, err := ParseIOCResponse([]byte(response))
	if err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	if resp.QueryStatus != "ok" {
		return nil, fmt.Errorf("API returned status: %s", resp.QueryStatus)
	}

	return resp.Data, nil
}

// QueryTag retrieves IOCs associated with a tag
func (c *Client) QueryTag(ctx context.Context, tag string, limit int) ([]IOC, error) {
	if err := ValidateTag(tag); err != nil {
		return nil, err
	}

	payload := map[string]interface{}{
		"query": "taginfo",
		"tag":   tag,
	}

	if limit > 0 {
		if err := ValidateLimit(limit); err != nil {
			return nil, err
		}
		payload["limit"] = limit
	}

	response, err := c.MakeRequest(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("error querying tag: %w", err)
	}

	resp, err := ParseIOCResponse([]byte(response))
	if err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	if resp.QueryStatus != "ok" {
		return nil, fmt.Errorf("API returned status: %s", resp.QueryStatus)
	}

	return resp.Data, nil
}

// QueryMalware retrieves IOCs associated with a malware family
func (c *Client) QueryMalware(ctx context.Context, malware string, limit int) ([]IOC, error) {
	if err := ValidateMalware(malware); err != nil {
		return nil, err
	}

	payload := map[string]interface{}{
		"query":   "malwareinfo",
		"malware": malware,
	}

	if limit > 0 {
		if err := ValidateLimit(limit); err != nil {
			return nil, err
		}
		payload["limit"] = limit
	}

	response, err := c.MakeRequest(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("error querying malware: %w", err)
	}

	resp, err := ParseIOCResponse([]byte(response))
	if err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	if resp.QueryStatus != "ok" {
		return nil, fmt.Errorf("API returned status: %s", resp.QueryStatus)
	}

	return resp.Data, nil
}

// GetMalwareList retrieves the list of supported malware families
func (c *Client) GetMalwareList(ctx context.Context) (map[string]MalwareDetails, error) {
	payload := map[string]interface{}{
		"query": "malware_list",
	}

	response, err := c.MakeRequest(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("error retrieving malware list: %w", err)
	}

	resp, err := ParseMalwareListResponse([]byte(response))
	if err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	if resp.QueryStatus != "ok" {
		return nil, fmt.Errorf("API returned status: %s", resp.QueryStatus)
	}

	return resp.Data, nil
}

// GetTypes retrieves the list of IOC/threat types
func (c *Client) GetTypes(ctx context.Context) (map[string]IOCType, error) {
	payload := map[string]interface{}{
		"query": "types",
	}

	response, err := c.MakeRequest(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("error retrieving types: %w", err)
	}

	resp, err := ParseTypesResponse([]byte(response))
	if err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	if resp.QueryStatus != "ok" {
		return nil, fmt.Errorf("API returned status: %s", resp.QueryStatus)
	}

	return resp.Data, nil
}

// GetTagList retrieves the list of known tags
func (c *Client) GetTagList(ctx context.Context) (map[string]TagInfo, error) {
	payload := map[string]interface{}{
		"query": "tag_list",
	}

	response, err := c.MakeRequest(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("error retrieving tag list: %w", err)
	}

	resp, err := ParseTagListResponse([]byte(response))
	if err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	if resp.QueryStatus != "ok" {
		return nil, fmt.Errorf("API returned status: %s", resp.QueryStatus)
	}

	return resp.Data, nil
}

// GetLabel identifies a malware name/label
func (c *Client) GetLabel(ctx context.Context, malware string, platform string) ([]LabelResult, error) {
	if err := ValidateMalware(malware); err != nil {
		return nil, err
	}

	payload := map[string]interface{}{
		"query":   "get_label",
		"malware": malware,
	}

	if platform != "" {
		payload["platform"] = platform
	}

	response, err := c.MakeRequest(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("error getting label: %w", err)
	}

	resp, err := ParseLabelResponse([]byte(response))
	if err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	if resp.QueryStatus != "ok" {
		return nil, fmt.Errorf("API returned status: %s", resp.QueryStatus)
	}

	return resp.Data, nil
}
