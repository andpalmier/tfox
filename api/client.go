package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// API constants
const (
	defaultAPIURL   = "https://threatfox-api.abuse.ch/api/v1/"
	defaultTimeout  = 30 * time.Second
	maxResponseSize = 64 * 1024 * 1024 // prevents OOM from large responses; get_iocs for 7 days is already over 11MB
)

// Client interacts with the ThreatFox API
type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
	interval   time.Duration
	lastReq    time.Time
	mu         sync.Mutex // Protects lastReq for thread-safe rate limiting
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

// wait handles simple rate limiting (thread-safe)
func (c *Client) wait() {
	c.mu.Lock()
	defer c.mu.Unlock()
	elapsed := time.Since(c.lastReq)
	if elapsed < c.interval {
		time.Sleep(c.interval - elapsed)
	}
	c.lastReq = time.Now()
}

// MakeRequest makes an HTTP POST request and returns the response as a string.
// It is kept for callers that use the exported string API; internal code uses
// makeRequest to avoid converting the body to a string and back.
func (c *Client) MakeRequest(ctx context.Context, payload interface{}) (string, error) {
	body, err := c.makeRequest(ctx, payload)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func (c *Client) makeRequest(ctx context.Context, payload interface{}) ([]byte, error) {
	c.wait()

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "tfox-client/1.0")
	if c.apiKey != "" {
		req.Header.Set("Auth-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %s", resp.Status)
	}

	limitedReader := io.LimitReader(resp.Body, maxResponseSize+1)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if len(body) > maxResponseSize {
		return nil, fmt.Errorf("response too large: exceeded %d bytes", maxResponseSize)
	}

	return body, nil
}
