package api

import (
	"context"
	"fmt"
)

// SubmitOptions describes an IOC submission. ThreatType, IOCType, Malware and
// IOCs are required; the rest are optional and omitted when empty.
//
// Valid ThreatType and IOCType values come from the types query, and valid
// Malware names from the malware_list query.
type SubmitOptions struct {
	ThreatType      string
	IOCType         string
	Malware         string
	IOCs            []string
	ConfidenceLevel int
	IsCompromised   bool
	Reference       string
	Tags            []string
	Comment         string
	Anonymous       bool
}

// SubmitIOC shares one or more indicators of compromise with ThreatFox.
func (c *Client) SubmitIOC(ctx context.Context, opts SubmitOptions) (*SubmitResponse, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}

	payload := map[string]interface{}{
		"query":       "submit_ioc",
		"threat_type": opts.ThreatType,
		"ioc_type":    opts.IOCType,
		"malware":     opts.Malware,
		"iocs":        opts.IOCs,
		"anonymous":   0,
	}
	if opts.Anonymous {
		payload["anonymous"] = 1
	}
	if opts.ConfidenceLevel > 0 {
		payload["confidence_level"] = opts.ConfidenceLevel
	}
	if opts.IsCompromised {
		payload["is_compromised"] = true
	}
	if opts.Reference != "" {
		payload["reference"] = opts.Reference
	}
	if opts.Comment != "" {
		payload["comment"] = opts.Comment
	}
	if len(opts.Tags) > 0 {
		payload["tags"] = opts.Tags
	}

	response, err := c.MakeRequest(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("error submitting IOCs: %w", err)
	}

	if err := CheckStatus([]byte(response), "submit_ioc"); err != nil {
		return nil, err
	}

	return ParseSubmitResponse([]byte(response))
}

// validate checks the fields the API requires before spending a request.
func (o SubmitOptions) validate() error {
	if o.ThreatType == "" {
		return fmt.Errorf("threat_type is required (see the types query for valid values)")
	}
	if o.IOCType == "" {
		return fmt.Errorf("ioc_type is required (see the types query for valid values)")
	}
	if o.Malware == "" {
		return fmt.Errorf("malware is required (see the malware_list query for valid names)")
	}
	if len(o.IOCs) == 0 {
		return fmt.Errorf("at least one IOC is required")
	}
	if o.ConfidenceLevel < 0 || o.ConfidenceLevel > 100 {
		return fmt.Errorf("confidence level must be between 0 and 100")
	}
	for _, t := range o.Tags {
		if err := ValidateTag(t); err != nil {
			return err
		}
	}
	return nil
}
