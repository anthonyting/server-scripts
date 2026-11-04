package ipdeny

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseFeed(t *testing.T) {
	got, err := parseFeed([]byte("# country ranges\n192.0.2.7/24\n\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{mustPrefix(t, "192.0.2.0/24")}
	if !equalPrefixes(got, want) {
		t.Fatalf("parseFeed() = %v, want %v", got, want)
	}
}

func TestParseFeedRejectsInvalidAndWrongFamily(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		wantIPv6 bool
	}{
		{name: "invalid CIDR", data: "not-an-address\n"},
		{name: "wrong family", data: "2001:db8::/32\n"},
		{name: "IPv4 mapped IPv6", data: "::ffff:192.0.2.0/120\n", wantIPv6: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseFeed([]byte(test.data), test.wantIPv6); err == nil {
				t.Fatal("parseFeed() succeeded; want an error")
			}
		})
	}
}

func TestFetchRejectsPartialFeedSet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ipblocks/data/countries/cn.zone" {
			_, _ = w.Write([]byte("192.0.2.0/24\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	transport := &rewriteTransport{base: server.Client().Transport, baseURL: server.URL}
	client := &http.Client{Transport: transport}
	prefixes, _, err := Fetch(context.Background(), client, []string{"CN"}, true, Cache{})
	if err == nil {
		t.Fatal("Fetch() succeeded with a missing IPv6 feed")
	}
	if prefixes != nil {
		t.Fatalf("Fetch() returned partial results: %v", prefixes)
	}
}

func TestFetchDoesNotIdentifyUpdater(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got != "" {
			t.Errorf("User-Agent = %q, want empty", got)
		}
		_, _ = w.Write([]byte("192.0.2.0/24\n"))
	}))
	defer server.Close()

	client := &http.Client{
		Transport: &rewriteTransport{base: server.Client().Transport, baseURL: server.URL},
	}
	if _, _, err := Fetch(context.Background(), client, []string{"CN"}, false, Cache{}); err != nil {
		t.Fatal(err)
	}
}

func TestFetchUsesFreshFileCache(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("192.0.2.0/24\n"))
	}))
	defer server.Close()

	client := &http.Client{
		Transport: &rewriteTransport{base: server.Client().Transport, baseURL: server.URL},
	}
	cache := Cache{Directory: t.TempDir(), TTL: 15 * time.Minute}
	ctx := context.Background()

	first, firstStats, err := Fetch(ctx, client, []string{"CN"}, false, cache)
	if err != nil {
		t.Fatal(err)
	}
	if firstStats.Downloads != 1 || firstStats.CacheHits != 0 {
		t.Fatalf("first Fetch() stats = %+v, want one download", firstStats)
	}

	second, secondStats, err := Fetch(ctx, client, []string{"CN"}, false, cache)
	if err != nil {
		t.Fatal(err)
	}
	if secondStats.CacheHits != 1 || secondStats.Downloads != 0 {
		t.Fatalf("second Fetch() stats = %+v, want one cache hit", secondStats)
	}
	if !equalPrefixes(first, second) {
		t.Fatalf("cached prefixes = %v, want %v", second, first)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("server requests = %d, want 1", got)
	}
}

func TestFetchRefreshesExpiredCache(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("192.0.2.0/24\n"))
	}))
	defer server.Close()

	client := &http.Client{
		Transport: &rewriteTransport{base: server.Client().Transport, baseURL: server.URL},
	}
	cache := Cache{Directory: t.TempDir(), TTL: time.Nanosecond}
	if _, _, err := Fetch(context.Background(), client, []string{"CN"}, false, cache); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	prefixes, stats, err := Fetch(context.Background(), client, []string{"CN"}, false, cache)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Downloads != 1 || stats.CacheHits != 0 {
		t.Fatalf("expired-cache Fetch() stats = %+v, want one download", stats)
	}
	if len(prefixes) != 1 || requests.Load() != 2 {
		t.Fatalf("prefixes=%v, requests=%d; want one prefix and two requests", prefixes, requests.Load())
	}
}

type rewriteTransport struct {
	base    http.RoundTripper
	baseURL string
}

func (t *rewriteTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = strings.TrimPrefix(t.baseURL, "http://")
	return t.base.RoundTrip(clone)
}

func mustPrefix(t *testing.T, value string) netip.Prefix {
	t.Helper()
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		t.Fatal(err)
	}
	return prefix
}

func equalPrefixes(left, right []netip.Prefix) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
