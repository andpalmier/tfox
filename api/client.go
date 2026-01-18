package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// API constants
const (
	defaultAPIURL   = "https://threatfox-api.abuse.ch/api/v1/"
	defaultTimeout  = 30 * time.Second
	maxResponseSize = 10 * 1024 * 1024 // prevents OOM from large responses (10MB)
)

// Client interacts with the ThreatFox API
type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
	interval   time.Duration
	lastReq    time.Time
}

// Option configures the Client
type Option func(*Client)

// WithTimeout sets the HTTP client timeout
func WithTimeout(timeout time.Duration) Option {
	return func(c *Client) {
		c.httpClient.Timeout = timeout
	}
}

// WithBaseURL sets the API base URL
func WithBaseURL(url string) Option {
	return func(c *Client) {
		c.baseURL = url
	}
}

// NewClient creates a new ThreatFox API client
// Note: API key is required
func NewClient(apiKey string, options ...Option) *Client {
	c := &Client{
		apiKey:   apiKey,
		baseURL:  defaultAPIURL,
		interval: 100 * time.Millisecond, // 10 requests per second
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
	}

	for _, opt := range options {
		opt(c)
	}

	return c
}

// wait handles simple rate limiting
func (c *Client) wait() {
	elapsed := time.Since(c.lastReq)
	if elapsed < c.interval {
		time.Sleep(c.interval - elapsed)
	}
	c.lastReq = time.Now()
}

// MakeRequest makes an HTTP POST request to the API with JSON body and returns the response
func (c *Client) MakeRequest(ctx context.Context, payload interface{}) (string, error) {
	c.wait()

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshaling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(jsonData))
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "tfox-client/1.0")
	if c.apiKey != "" {
		req.Header.Set("Auth-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API returned status %s", resp.Status)
	}

	limitedReader := io.LimitReader(resp.Body, maxResponseSize)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}

	if len(body) == maxResponseSize {
		return "", fmt.Errorf("response too large: exceeded %d bytes", maxResponseSize)
	}

	return string(body), nil
}
