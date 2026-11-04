package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"country-ip-blocklist/internal/firewall"
	"country-ip-blocklist/internal/ipdeny"
)

const (
	defaultCountries = "CN,RU,TW,UA,NG"
	defaultRuleName  = "CountryIPBlocklist"
)

var ruleNamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "country-ip-blocklist:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("country-ip-blocklist", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	countryFlag := flags.String("countries", defaultCountries, "comma-separated ISO 3166-1 alpha-2 country codes")
	ipv6 := flags.Bool("ipv6", true, "include IPdeny IPv6 feeds")
	dryRun := flags.Bool("dry-run", false, "fetch, validate, and summarize feeds without changing the firewall")
	ruleName := flags.String("rule-name", defaultRuleName, "name of the managed Windows Firewall rule")
	timeout := flags.Duration("timeout", 45*time.Second, "maximum time allowed to fetch all feeds")
	cacheTTL := flags.Duration("cache-ttl", 15*time.Minute, "how long validated IPdeny feeds are reused from disk")
	cacheDir := flags.String("cache-dir", "", "directory for cached feeds (defaults to the user's cache directory)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(flags.Args(), " "))
	}
	if !ruleNamePattern.MatchString(*ruleName) {
		return fmt.Errorf("invalid rule name %q; use 1-128 letters, digits, dots, underscores, or hyphens", *ruleName)
	}
	if *timeout <= 0 {
		return errors.New("timeout must be greater than zero")
	}
	if *cacheTTL < 0 {
		return errors.New("cache TTL cannot be negative")
	}

	countries, err := parseCountries(*countryFlag)
	if err != nil {
		return err
	}
	if !*dryRun {
		if err := firewall.CheckReady(); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if *cacheDir == "" && *cacheTTL > 0 {
		userCacheDir, err := os.UserCacheDir()
		if err != nil {
			return fmt.Errorf("resolve user cache directory: %w", err)
		}
		*cacheDir = filepath.Join(userCacheDir, "country-ip-blocklist")
	}
	prefixes, stats, err := ipdeny.Fetch(ctx, &http.Client{Timeout: *timeout}, countries, *ipv6,
		ipdeny.Cache{Directory: *cacheDir, TTL: *cacheTTL})
	if err != nil {
		return err
	}
	rawCount := len(prefixes)
	prefixes = ipdeny.Merge(prefixes)
	if len(prefixes) == 0 {
		return errors.New("the combined IPdeny feeds contain no IP ranges")
	}

	ipv4Count, ipv6Count := 0, 0
	for _, prefix := range prefixes {
		if prefix.Addr().Is4() {
			ipv4Count++
		} else {
			ipv6Count++
		}
	}
	fmt.Printf("Prepared %d raw CIDRs; merged to %d (%d IPv4, %d IPv6) from %s.\n",
		rawCount, len(prefixes), ipv4Count, ipv6Count, strings.Join(countries, ","))
	fmt.Printf("IPdeny feeds: %d cached, %d downloaded.\n", stats.CacheHits, stats.Downloads)
	if *dryRun {
		fmt.Println("Dry run: Windows Firewall was not changed.")
		return nil
	}

	return firewall.Apply(*ruleName, prefixes)
}

func parseCountries(value string) ([]string, error) {
	parts := strings.Split(value, ",")
	countries := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		country := strings.ToUpper(strings.TrimSpace(part))
		if len(country) != 2 || country[0] < 'A' || country[0] > 'Z' ||
			country[1] < 'A' || country[1] > 'Z' {
			return nil, fmt.Errorf("invalid country code %q; expected two ASCII letters", part)
		}
		if _, ok := seen[country]; ok {
			continue
		}
		seen[country] = struct{}{}
		countries = append(countries, country)
	}
	if len(countries) == 0 {
		return nil, errors.New("at least one country code is required")
	}
	return countries, nil
}
