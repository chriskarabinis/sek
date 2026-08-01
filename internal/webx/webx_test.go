package webx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMaxScore(t *testing.T) {
	if got, want := MaxScore(), 11; got != want {
		t.Errorf("MaxScore() = %d, want %d", got, want)
	}
}

// TestScoringIsWeighted guards the point of weighting: the headers that matter
// most must move the score more than the ones that matter least.
func TestScoringIsWeighted(t *testing.T) {
	weights := make(map[string]int)
	for _, sh := range SecurityHeaders {
		weights[sh.Key] = sh.Weight
	}
	if weights["Content-Security-Policy"] <= weights["Permissions-Policy"] {
		t.Error("Content-Security-Policy must be worth more than Permissions-Policy")
	}
	if weights["Strict-Transport-Security"] <= weights["X-Content-Type-Options"] {
		t.Error("Strict-Transport-Security must be worth more than X-Content-Type-Options")
	}
}

// TestXXSSProtectionIsNotScored is the regression test for the old behaviour:
// the header was rewarded when present and recommended when absent, which is
// the opposite of current guidance.
func TestXXSSProtectionIsNotScored(t *testing.T) {
	for _, sh := range SecurityHeaders {
		if sh.Key == "X-XSS-Protection" {
			t.Fatal("X-XSS-Protection must not count toward the score")
		}
	}

	var found bool
	for _, sh := range DeprecatedHeaders {
		if sh.Key == "X-XSS-Protection" {
			found = true
			if !strings.Contains(strings.ToLower(sh.Fix), "remove") {
				t.Errorf("advice for X-XSS-Protection is %q, expected it to say remove", sh.Fix)
			}
		}
	}
	if !found {
		t.Error("X-XSS-Protection must be listed as deprecated")
	}
}

func TestRating(t *testing.T) {
	tests := []struct {
		name   string
		earned int
		total  int
		want   string
	}{
		{"perfect", 11, 11, "Excellent"},
		{"good lower bound", 8, 11, "Good"},
		{"fair", 5, 11, "Fair"},
		{"poor", 2, 11, "Poor"},
		{"nothing", 0, 11, "Poor"},
		{"guards divide by zero", 0, 0, "Unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Rating(tt.earned, tt.total); got != tt.want {
				t.Errorf("Rating(%d, %d) = %q, want %q", tt.earned, tt.total, got, tt.want)
			}
		})
	}
}

func TestBuildURL(t *testing.T) {
	tests := []struct {
		name string
		opts Options
		want string
	}{
		{"https by default", Options{}, "https://example.com"},
		{"plain http", Options{UseHTTP: true}, "http://example.com"},
		{"custom port", Options{Port: "8443"}, "https://example.com:8443"},
		{"http with port", Options{UseHTTP: true, Port: "8080"}, "http://example.com:8080"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := BuildURL("example.com", tt.opts); got != tt.want {
				t.Errorf("BuildURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCheckHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	target, port, _ := strings.Cut(host, ":")

	res, err := CheckHeaders(context.Background(), target, Options{UseHTTP: true, Port: port})
	if err != nil {
		t.Fatalf("CheckHeaders returned error: %v", err)
	}

	// HSTS (3) + X-Frame-Options (2); the deprecated header adds nothing.
	if res.Score != 5 {
		t.Errorf("Score = %d, want 5", res.Score)
	}
	if len(res.Deprecated) != 1 || res.Deprecated[0].Header != "X-XSS-Protection" {
		t.Errorf("Deprecated = %+v, want one X-XSS-Protection entry", res.Deprecated)
	}
	if got := len(res.Missing()); got != 4 {
		t.Errorf("Missing() returned %d headers, want 4", got)
	}
	if res.Server != "nginx/1.18.0" {
		t.Errorf("Server = %q, want %q", res.Server, "nginx/1.18.0")
	}
	if res.Redirected {
		t.Error("Redirected = true for a response that was not redirected")
	}
}

// TestCheckHeadersReportsRedirect covers the case where the headers described
// belong to an origin other than the one requested.
func TestCheckHeadersReportsRedirect(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer final.Close()

	start := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL, http.StatusFound)
	}))
	defer start.Close()

	host := strings.TrimPrefix(start.URL, "http://")
	target, port, _ := strings.Cut(host, ":")

	res, err := CheckHeaders(context.Background(), target, Options{UseHTTP: true, Port: port})
	if err != nil {
		t.Fatalf("CheckHeaders returned error: %v", err)
	}
	if !res.Redirected {
		t.Error("Redirected = false after following a redirect")
	}
	if res.FinalURL == res.URL {
		t.Errorf("FinalURL = %q, expected it to differ from %q", res.FinalURL, res.URL)
	}
}

// TestFingerprintIgnoresProse is the regression test for matching bare product
// names anywhere in the markup: an article merely mentioning these libraries
// was reported as using all of them.
func TestFingerprintIgnoresProse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><article>
			How to bootstrap a startup. Many still reach for jquery, though
			tailwind and react changed things, and our angular days are over.
		</article></body></html>`))
	}))
	defer srv.Close()

	res := fingerprintTestServer(t, srv)
	if len(res.Technologies) != 0 {
		t.Errorf("detected %+v from prose alone, want nothing", res.Technologies)
	}
}

// TestFingerprintDetectsRealAssets is the other half: genuine asset references
// must still be found, with versions where the response reveals them.
func TestFingerprintDetectsRealAssets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Set("X-Powered-By", "PHP/8.1.2")
		w.Header().Set("Content-Type", "text/html")
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "abc"})
		w.Write([]byte(`<html><head>
			<script src="/js/jquery-3.6.0.min.js"></script>
			<link href="/css/bootstrap.min.css" rel="stylesheet">
			<meta name="generator" content="WordPress 6.4">
		</head><body>hello</body></html>`))
	}))
	defer srv.Close()

	res := fingerprintTestServer(t, srv)

	got := make(map[string]string)
	for _, tech := range res.Technologies {
		got[tech.Name] = tech.Version
	}

	for _, want := range []string{"nginx", "PHP", "WordPress", "jQuery", "Bootstrap"} {
		if _, ok := got[want]; !ok {
			t.Errorf("%s not detected; got %v", want, got)
		}
	}
	if got["nginx"] != "1.18.0" {
		t.Errorf("nginx version = %q, want %q", got["nginx"], "1.18.0")
	}
	if got["PHP"] != "8.1.2" {
		t.Errorf("PHP version = %q, want %q", got["PHP"], "8.1.2")
	}
}

// TestSignaturePatternsAreLowercase guards the assumption match() relies on.
// Fingerprint folds the response body before calling match, and match folds
// each header value before comparing it against HeaderVal — but neither folds
// the table, so a pattern written with a capital letter would never fire.
func TestSignaturePatternsAreLowercase(t *testing.T) {
	for _, sig := range Signatures {
		if got := strings.ToLower(sig.HeaderVal); got != sig.HeaderVal {
			t.Errorf("%s: HeaderVal %q is not lower-case", sig.Name, sig.HeaderVal)
		}
		for _, pattern := range sig.Body {
			if got := strings.ToLower(pattern); got != pattern {
				t.Errorf("%s: body pattern %q is not lower-case", sig.Name, pattern)
			}
		}
	}
}

// TestSignatureCategoriesAreKnown catches a signature filed under a category
// the renderer does not list, which would silently drop it from the output.
func TestSignatureCategoriesAreKnown(t *testing.T) {
	known := make(map[string]bool, len(Categories))
	for _, c := range Categories {
		known[c] = true
	}
	for _, sig := range Signatures {
		if !known[sig.Category] {
			t.Errorf("%s: category %q is not in Categories", sig.Name, sig.Category)
		}
	}
}

func fingerprintTestServer(t *testing.T, srv *httptest.Server) *TechResult {
	t.Helper()
	host := strings.TrimPrefix(srv.URL, "http://")
	target, port, _ := strings.Cut(host, ":")

	res, err := Fingerprint(context.Background(), target, Options{UseHTTP: true, Port: port})
	if err != nil {
		t.Fatalf("Fingerprint returned error: %v", err)
	}
	return res
}
