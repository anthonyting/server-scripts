package ipdeny

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const maxFeedBytes = 16 << 20

type feed struct {
	country string
	ipv6    bool
}

type feedResult struct {
	index    int
	prefixes []netip.Prefix
	cached   bool
	err      error
}

// FetchStats reports how many feeds came from disk or were downloaded.
type FetchStats struct {
	CacheHits int
	Downloads int
}

// Fetch downloads and validates all requested country feeds before returning.
func Fetch(ctx context.Context, client *http.Client, countries []string, includeIPv6 bool, cache Cache) ([]netip.Prefix, FetchStats, error) {
	var sources []feed
	for _, country := range countries {
		sources = append(sources, feed{country: country})
		if includeIPv6 {
			sources = append(sources, feed{country: country, ipv6: true})
		}
	}
	if len(sources) == 0 {
		return nil, FetchStats{}, errors.New("at least one country feed is required")
	}

	if cache.TTL > 0 && cache.Directory == "" {
		return nil, FetchStats{}, errors.New("cache directory is required when cache TTL is enabled")
	}
	results := make(chan feedResult, len(sources))
	semaphore := make(chan struct{}, 4)
	var workers sync.WaitGroup
	for i, source := range sources {
		workers.Add(1)
		go func(index int, source feed) {
			defer workers.Done()
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				results <- feedResult{index: index, err: ctx.Err()}
				return
			}

			prefixes, cached, err := fetchFeed(ctx, client, source, cache)
			results <- feedResult{index: index, prefixes: prefixes, cached: cached, err: err}
		}(i, source)
	}
	workers.Wait()
	close(results)

	ordered := make([]feedResult, len(sources))
	for result := range results {
		ordered[result.index] = result
	}

	var allPrefixes []netip.Prefix
	var failures []string
	var stats FetchStats
	for i, result := range ordered {
		if result.err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", feedURL(sources[i]), result.err))
			continue
		}
		allPrefixes = append(allPrefixes, result.prefixes...)
		if result.cached {
			stats.CacheHits++
		} else {
			stats.Downloads++
		}
	}
	if len(failures) != 0 {
		return nil, FetchStats{}, fmt.Errorf("one or more IPdeny feeds failed; firewall was not changed:\n  %s",
			strings.Join(failures, "\n  "))
	}
	return allPrefixes, stats, nil
}

func feedURL(source feed) string {
	country := strings.ToLower(source.country)
	if source.ipv6 {
		return fmt.Sprintf("https://www.ipdeny.com/ipv6/ipaddresses/blocks/%s.zone", country)
	}
	return fmt.Sprintf("https://www.ipdeny.com/ipblocks/data/countries/%s.zone", country)
}

func fetchFeed(ctx context.Context, client *http.Client, source feed, cache Cache) ([]netip.Prefix, bool, error) {
	if prefixes, ok, err := cache.load(source, time.Now()); err != nil {
		return nil, false, fmt.Errorf("load %s cache: %w", source.country, err)
	} else if ok {
		return prefixes, true, nil
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL(source), nil)
	if err != nil {
		return nil, false, err
	}
	request.Header["User-Agent"] = []string{""}

	response, err := client.Do(request)
	if err != nil {
		return nil, false, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("unexpected HTTP status %s", response.Status)
	}

	data, err := io.ReadAll(io.LimitReader(response.Body, maxFeedBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("read response: %w", err)
	}
	if len(data) > maxFeedBytes {
		return nil, false, fmt.Errorf("feed exceeds %d bytes", maxFeedBytes)
	}
	prefixes, err := parseFeed(data, source.ipv6)
	if err != nil {
		return nil, false, err
	}
	if len(prefixes) == 0 {
		return nil, false, errors.New("feed contains no CIDRs")
	}
	if err := cache.store(source, prefixes, time.Now()); err != nil {
		return nil, false, fmt.Errorf("store %s cache: %w", source.country, err)
	}
	return prefixes, false, nil
}

func parseFeed(data []byte, wantIPv6 bool) ([]netip.Prefix, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 1024), 1024)
	prefixes := make([]netip.Prefix, 0)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR on line %d: %w", lineNumber, err)
		}
		isIPv6 := prefix.Addr().Is6() && !prefix.Addr().Is4In6()
		if isIPv6 != wantIPv6 {
			return nil, fmt.Errorf("CIDR on line %d has the wrong address family", lineNumber)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read feed: %w", err)
	}
	return prefixes, nil
}
