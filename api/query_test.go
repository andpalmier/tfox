package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_GetRecentIOCs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Auth-Key header is sent
		authKey := r.Header.Get("Auth-Key")
		if authKey != "test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{
			"query_status": "ok",
			"data": [
				{
					"id": "123",
					"ioc": "1.2.3.4",
					"threat_type": "botnet_cc",
					"malware": "Emotet"
				}
			]
		}`)
	}))
	defer server.Close()

	c := NewClient("test-key")
	c.baseURL = server.URL + "/"

	iocs, err := c.GetRecentIOCs(context.Background(), 1)
	if err != nil {
		t.Fatalf("GetRecentIOCs() error = %v", err)
	}
	if len(iocs) != 1 {
		t.Errorf("Expected 1 result, got %d", len(iocs))
	}
	if iocs[0].IOC != "1.2.3.4" {
		t.Errorf("Got wrong IOC: %s", iocs[0].IOC)
	}
}

func TestClient_QueryIOC(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Auth-Key header is sent
		authKey := r.Header.Get("Auth-Key")
		if authKey != "test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{
	"id": "123",
	"ioc": "1.2.3.4",
	"threat_type": "botnet_cc",
	"threat_type_desc": "test",
	"ioc_type": "ip:port",
	"ioc_type_desc": "test",
	"malware": "Emotet",
	"malware_printable": "Emotet",
	"malware_malpedia": "https://example.com",
	"confidence_level": 75,
	"first_seen": "2024-01-01 00:00:00 UTC",
	"reporter": "test"
}`)
	}))
	defer server.Close()

	c := NewClient("test-key")
	c.baseURL = server.URL + "/"

	ioc, err := c.GetIOCByID(context.Background(), 123)
	if err != nil {
		t.Fatalf("GetIOCByID() error = %v", err)
	}
	if ioc.ID != "123" {
		t.Errorf("Expected ID 123, got %s", ioc.ID)
	}
}

func TestClient_SearchIOC(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Auth-Key header is sent
		authKey := r.Header.Get("Auth-Key")
		if authKey != "test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{
			"query_status": "ok",
			"data": [
				{
					"id": "123",
					"ioc": "1.2.3.4"
				}
			]
		}`)
	}))
	defer server.Close()

	c := NewClient("test-key")
	c.baseURL = server.URL + "/"

	iocs, err := c.SearchIOC(context.Background(), "1.2.3.4", false)
	if err != nil {
		t.Fatalf("SearchIOC() error = %v", err)
	}
	if len(iocs) != 1 {
		t.Errorf("Expected 1 result")
	}
}
