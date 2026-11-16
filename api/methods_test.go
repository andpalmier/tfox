package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

const methodsSHA256 = "d41d8cd98f00b204e9800998ecf8427e00000000000000000000000000000000"

func tfoxTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return NewClient("test-key", WithBaseURL(server.URL+"/"))
}

func decodeJSONBody(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	return payload
}

func TestQueryMethodsForwardParameters(t *testing.T) {
	tests := []struct {
		name  string
		query string
		check func(*testing.T, map[string]any)
		call  func(context.Context, *Client) (any, error)
	}{
		{"search by hash", "search_hash", func(t *testing.T, p map[string]any) {
			if p["hash"] != methodsSHA256 {
				t.Errorf("hash = %v", p["hash"])
			}
		}, func(ctx context.Context, c *Client) (any, error) {
			return c.SearchByHash(ctx, methodsSHA256)
		}},
		{"tag", "taginfo", func(t *testing.T, p map[string]any) {
			if p["tag"] != "Emotet" || p["limit"] != float64(10) {
				t.Errorf("tag payload = %#v", p)
			}
		}, func(ctx context.Context, c *Client) (any, error) {
			return c.QueryTag(ctx, "Emotet", 10)
		}},
		{"malware", "malwareinfo", func(t *testing.T, p map[string]any) {
			if p["malware"] != "Emotet" || p["limit"] != float64(10) {
				t.Errorf("malware payload = %#v", p)
			}
		}, func(ctx context.Context, c *Client) (any, error) {
			return c.QueryMalware(ctx, "Emotet", 10)
		}},
		{"malware list", "malware_list", func(t *testing.T, p map[string]any) {}, func(ctx context.Context, c *Client) (any, error) {
			return c.GetMalwareList(ctx)
		}},
		{"types", "types", func(t *testing.T, p map[string]any) {}, func(ctx context.Context, c *Client) (any, error) {
			return c.GetTypes(ctx)
		}},
		{"tag list", "tag_list", func(t *testing.T, p map[string]any) {}, func(ctx context.Context, c *Client) (any, error) {
			return c.GetTagList(ctx)
		}},
		{"label", "get_label", func(t *testing.T, p map[string]any) {
			if p["malware"] != "Emotet" || p["platform"] != "windows" {
				t.Errorf("label payload = %#v", p)
			}
		}, func(ctx context.Context, c *Client) (any, error) {
			return c.GetLabel(ctx, "Emotet", "windows")
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tfoxTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				payload := decodeJSONBody(t, r)
				if payload["query"] != tt.query {
					t.Errorf("query = %v, want %q", payload["query"], tt.query)
				}
				tt.check(t, payload)
				w.Header().Set("Content-Type", "application/json")
				switch tt.query {
				case "malware_list":
					_, _ = fmt.Fprint(w, `{"query_status":"ok","data":{"Emotet":{"malware_printable":"Emotet"}}}`)
				case "types":
					_, _ = fmt.Fprint(w, `{"query_status":"ok","data":{"botnet_cc":{"ioc_type":"domain","fk_threat_type":"botnet_cc","description":"C2"}}}`)
				case "tag_list":
					_, _ = fmt.Fprint(w, `{"query_status":"ok","data":{"Emotet":{"first_seen":"2024-01-01","last_seen":"2024-01-02","color":"red"}}}`)
				case "get_label":
					_, _ = fmt.Fprint(w, `{"query_status":"ok","data":[{"malware":"Emotet","malware_printable":"Emotet"}]}`)
				default:
					_, _ = fmt.Fprint(w, `{"query_status":"ok","data":[{"id":"1","ioc":"1.2.3.4"}]}`)
				}
			})

			got, err := tt.call(context.Background(), c)
			if err != nil {
				t.Fatalf("call failed: %v", err)
			}
			switch v := got.(type) {
			case []IOC:
				if len(v) != 1 || v[0].IOC != "1.2.3.4" {
					t.Errorf("IOC result = %+v", v)
				}
			case map[string]MalwareDetails:
				if v["Emotet"].MalwarePrintable != "Emotet" {
					t.Errorf("malware list = %+v", v)
				}
			case map[string]IOCType:
				if v["botnet_cc"].IOCType != "domain" {
					t.Errorf("types = %+v", v)
				}
			case map[string]TagInfo:
				if v["Emotet"].Color != "red" {
					t.Errorf("tags = %+v", v)
				}
			case []LabelResult:
				if len(v) != 1 || v[0].MalwarePrintable != "Emotet" {
					t.Errorf("labels = %+v", v)
				}
			default:
				t.Fatalf("unexpected return type %T", got)
			}
		})
	}
}

func TestSubmitIOCWireFormat(t *testing.T) {
	var got map[string]any
	c := tfoxTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		got = decodeJSONBody(t, r)
		_, _ = fmt.Fprint(w, `{"query_status":"ok","data":{"accepted":2}}`)
	})

	resp, err := c.SubmitIOC(context.Background(), SubmitOptions{
		ThreatType:      "botnet_cc",
		IOCType:         "domain",
		Malware:         "Emotet",
		IOCs:            []string{"evil.example", "evil2.example"},
		ConfidenceLevel: 80,
		IsCompromised:   true,
		Reference:       "https://example.test/report",
		Tags:            []string{"c2", "emotet"},
		Comment:         "test",
		Anonymous:       true,
	})
	if err != nil {
		t.Fatalf("SubmitIOC: %v", err)
	}
	if string(resp.Data) != `{"accepted":2}` {
		t.Errorf("raw data = %s", resp.Data)
	}
	checks := map[string]any{
		"query":            "submit_ioc",
		"threat_type":      "botnet_cc",
		"ioc_type":         "domain",
		"malware":          "Emotet",
		"confidence_level": float64(80),
		"is_compromised":   true,
		"reference":        "https://example.test/report",
		"comment":          "test",
		"anonymous":        float64(1),
	}
	for key, want := range checks {
		if got[key] != want {
			t.Errorf("%s = %#v, want %#v", key, got[key], want)
		}
	}
	iocs, ok := got["iocs"].([]any)
	if !ok || len(iocs) != 2 || iocs[0] != "evil.example" {
		t.Errorf("iocs = %#v", got["iocs"])
	}
}

func TestSubmitIOCSendsExplicitZeroConfidence(t *testing.T) {
	var got map[string]any
	c := tfoxTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		got = decodeJSONBody(t, r)
		_, _ = fmt.Fprint(w, `{"query_status":"ok","data":{"accepted":1}}`)
	})

	_, err := c.SubmitIOC(context.Background(), SubmitOptions{
		ThreatType:         "botnet_cc",
		IOCType:            "domain",
		Malware:            "Emotet",
		IOCs:               []string{"evil.example"},
		ConfidenceLevel:    0,
		ConfidenceLevelSet: true,
	})
	if err != nil {
		t.Fatalf("SubmitIOC: %v", err)
	}
	value, ok := got["confidence_level"]
	if !ok || value != float64(0) {
		t.Errorf("confidence_level = %#v, present = %v; want explicit 0", value, ok)
	}
}

func TestSubmitIOCValidation(t *testing.T) {
	tests := []struct {
		name string
		opts SubmitOptions
	}{
		{"missing threat type", SubmitOptions{IOCType: "domain", Malware: "Emotet", IOCs: []string{"x"}}},
		{"missing ioc type", SubmitOptions{ThreatType: "botnet_cc", Malware: "Emotet", IOCs: []string{"x"}}},
		{"missing malware", SubmitOptions{ThreatType: "botnet_cc", IOCType: "domain", IOCs: []string{"x"}}},
		{"missing iocs", SubmitOptions{ThreatType: "botnet_cc", IOCType: "domain", Malware: "Emotet"}},
		{"confidence high", SubmitOptions{ThreatType: "botnet_cc", IOCType: "domain", Malware: "Emotet", IOCs: []string{"x"}, ConfidenceLevel: 101}},
		{"bad tag", SubmitOptions{ThreatType: "botnet_cc", IOCType: "domain", Malware: "Emotet", IOCs: []string{"x"}, Tags: []string{"bad/tag"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.opts.validate(); err == nil {
				t.Error("expected validation error")
			}
		})
	}
}

func TestParseIOCResponseWithoutStatus(t *testing.T) {
	resp, err := ParseIOCResponse([]byte(`{"data":[{"id":"1","ioc":"1.2.3.4"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.QueryStatus != "" {
		t.Errorf("missing query_status became %q, want empty", resp.QueryStatus)
	}
}

func TestQueryMethodsRejectNegativeLimitBeforeNetwork(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"query_status":"ok","data":[]}`)
	}))
	defer server.Close()

	c := NewClient("test-key", WithBaseURL(server.URL+"/"))
	ctx := context.Background()
	if _, err := c.QueryTag(ctx, "Emotet", -1); err == nil {
		t.Error("QueryTag accepted a negative limit")
	}
	if _, err := c.QueryMalware(ctx, "Emotet", -1); err == nil {
		t.Error("QueryMalware accepted a negative limit")
	}
	if got := requests.Load(); got != 0 {
		t.Errorf("API was contacted %d times for negative limits", got)
	}
}

func TestParseIOCResponseIgnoresErrorStringData(t *testing.T) {
	resp, err := ParseIOCResponse([]byte(`{"query_status":"error","data":"bad search"}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.QueryStatus != "error" || len(resp.Data) != 0 {
		t.Errorf("response = %+v, want error status and no IOC rows", resp)
	}
}
