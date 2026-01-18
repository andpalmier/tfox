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

	iocs, err := c.GetIOCByID(context.Background(), 123)
	if err != nil {
		t.Fatalf("GetIOCByID() error = %v", err)
	}
	if iocs == nil {
		t.Errorf("Expected result")
	}
}

func TestClient_SearchIOC(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
