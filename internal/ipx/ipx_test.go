package ipx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLookup(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"status": "success",
			"query": "8.8.8.8",
			"country": "United States",
			"countryCode": "US",
			"regionName": "Virginia",
			"city": "Ashburn",
			"lat": 39.03,
			"lon": -77.5,
			"timezone": "America/New_York",
			"isp": "Google LLC",
			"org": "Google Public DNS",
			"as": "AS15169 Google LLC"
		}`))
	}))
	defer srv.Close()

	restore := swapEndpoint(srv.URL + "/json/")
	defer restore()

	res, err := Lookup(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}

	if !strings.HasSuffix(gotPath, "8.8.8.8") {
		t.Errorf("requested path = %q, want it to end with the address", gotPath)
	}
	if res.IP != "8.8.8.8" {
		t.Errorf("IP = %q, want 8.8.8.8", res.IP)
	}
	if res.Country != "United States" || res.CountryCode != "US" {
		t.Errorf("country = %q (%q)", res.Country, res.CountryCode)
	}
	if res.ISP != "Google LLC" {
		t.Errorf("ISP = %q", res.ISP)
	}
	if res.ASN != "AS15169 Google LLC" {
		t.Errorf("ASN = %q", res.ASN)
	}
	if res.Target != "8.8.8.8" {
		t.Errorf("Target = %q", res.Target)
	}
}

// TestLookupReportsAPIFailure covers the service answering with a body that
// says failure while the HTTP status is still 200.
func TestLookupReportsAPIFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"fail","message":"reserved range","query":"127.0.0.1"}`))
	}))
	defer srv.Close()

	restore := swapEndpoint(srv.URL + "/json/")
	defer restore()

	_, err := Lookup(context.Background(), "127.0.0.1")
	if err == nil {
		t.Fatal("Lookup returned no error for a failed lookup")
	}
	if !strings.Contains(err.Error(), "reserved range") {
		t.Errorf("error = %q, want it to carry the API message", err)
	}
}

func TestLookupReportsHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	restore := swapEndpoint(srv.URL + "/json/")
	defer restore()

	if _, err := Lookup(context.Background(), "8.8.8.8"); err == nil {
		t.Error("Lookup returned no error for HTTP 429")
	}
}

func swapEndpoint(url string) func() {
	previous := endpoint
	endpoint = url
	return func() { endpoint = previous }
}
