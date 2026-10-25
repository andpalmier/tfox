package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
)

// exportsURL is where abuse.ch serves the bulk data exports. Unlike the query
// API, the Auth-Key travels in the URL path rather than in a header.
var exportsURL = "https://threatfox-api.abuse.ch/v2/files/exports/"

// ExportFile is a bulk data export ThreatFox publishes.
type ExportFile struct {
	Name        string
	Description string
}

// ExportFiles lists the exports ThreatFox serves. The documentation only shows
// the file names after login; these were confirmed against the live endpoint.
var ExportFiles = []ExportFile{
	{"recent.csv", "IOCs added recently (CSV)"},
	{"recent.json", "IOCs added recently (JSON)"},
	{"full.csv.zip", "Every IOC from the past 6 months (zipped CSV)"},
	{"full.json.zip", "Every IOC from the past 6 months (zipped JSON)"},
	{"hostfile.txt", "Hosts file of payload delivery and botnet C2 domains"},
	{"threatfox.rpz", "DNS Response Policy Zone of the same domains"},
	{"threatfox_suricata.rules", "Suricata IDS ruleset of network IOCs"},
	{"threatfox_suricata.tar.gz", "Suricata IDS ruleset of network IOCs (tar.gz)"},
}

// exportNameRegex keeps the file name a single path segment, since it is used
// both in the URL and as the default output path.
var exportNameRegex = regexp.MustCompile(`^[A-Za-z0-9_-]+(\.[A-Za-z0-9]+)+$`)

// DownloadExport downloads the bulk export fileName and writes it to outPath.
// When outPath is empty the file keeps its export name in the working
// directory. It returns the path written.
func (c *Client) DownloadExport(ctx context.Context, fileName, outPath string) (string, error) {
	if !exportNameRegex.MatchString(fileName) {
		return "", fmt.Errorf("invalid export file name %q", fileName)
	}

	if outPath == "" {
		outPath = fileName
	}

	if _, err := os.Stat(outPath); err == nil {
		return "", fmt.Errorf("file already exists: %s", outPath)
	}

	c.wait()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, exportsURL+url.PathEscape(c.apiKey)+"/"+fileName, nil)
	if err != nil {
		// The URL carries the API key, so the error is not wrapped.
		return "", errors.New("creating request failed")
	}
	req.Header.Set("User-Agent", "tfox-client/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Drop the URL, and with it the API key, from the error.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", exportError(resp)
	}

	out, err := os.Create(outPath)
	if err != nil {
		return "", fmt.Errorf("error creating file: %w", err)
	}

	if _, err := io.Copy(out, resp.Body); err != nil {
		_ = out.Close()
		_ = os.Remove(outPath)
		return "", fmt.Errorf("error saving file: %w", err)
	}

	if err := out.Close(); err != nil {
		return "", fmt.Errorf("error saving file: %w", err)
	}

	return outPath, nil
}

// exportError explains a failed export download. The API answers with JSON
// such as {"status":404,"message":"Invalid export file name"}.
func exportError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var js struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &js) == nil && js.Message != "" {
		return fmt.Errorf("export failed: %s (%s)", js.Message, resp.Status)
	}
	return fmt.Errorf("API returned status %s", resp.Status)
}
