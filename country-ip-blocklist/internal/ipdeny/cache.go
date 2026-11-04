package ipdeny

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

const cacheVersion = 1

// Cache stores validated country feeds for a bounded time.
type Cache struct {
	Directory string
	TTL       time.Duration
}

type cacheEntry struct {
	Version   int       `json:"version"`
	FetchedAt time.Time `json:"fetched_at"`
	Prefixes  []string  `json:"prefixes"`
}

func (c Cache) load(source feed, now time.Time) ([]netip.Prefix, bool, error) {
	if c.TTL <= 0 {
		return nil, false, nil
	}
	data, err := os.ReadFile(c.filePath(source))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read cache: %w", err)
	}

	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, false, fmt.Errorf("decode cache: %w", err)
	}
	age := now.Sub(entry.FetchedAt)
	if entry.Version != cacheVersion || entry.FetchedAt.IsZero() ||
		age < 0 || age >= c.TTL || len(entry.Prefixes) == 0 {
		return nil, false, nil
	}
	prefixes, err := parseFeed([]byte(strings.Join(entry.Prefixes, "\n")), source.ipv6)
	if err != nil || len(prefixes) == 0 {
		if err == nil {
			err = errors.New("cache entry contains no CIDRs")
		}
		return nil, false, fmt.Errorf("validate cache: %w", err)
	}
	return prefixes, true, nil
}

func (c Cache) store(source feed, prefixes []netip.Prefix, now time.Time) error {
	if c.TTL <= 0 {
		return nil
	}
	if err := os.MkdirAll(c.Directory, 0o700); err != nil {
		return fmt.Errorf("create cache directory: %w", err)
	}

	entry := cacheEntry{
		Version:   cacheVersion,
		FetchedAt: now.UTC(),
		Prefixes:  make([]string, len(prefixes)),
	}
	for i, prefix := range prefixes {
		entry.Prefixes[i] = prefix.Masked().String()
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encode cache: %w", err)
	}

	file, err := os.CreateTemp(c.Directory, "feed-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary cache file: %w", err)
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)
	if _, err := file.Write(data); err != nil {
		file.Close()
		return fmt.Errorf("write temporary cache file: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("flush temporary cache file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary cache file: %w", err)
	}

	targetPath := c.filePath(source)
	oldName, err := windows.UTF16PtrFromString(tempPath)
	if err != nil {
		return fmt.Errorf("encode temporary cache path: %w", err)
	}
	newName, err := windows.UTF16PtrFromString(targetPath)
	if err != nil {
		return fmt.Errorf("encode cache path: %w", err)
	}
	if err := windows.MoveFileEx(oldName, newName, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return fmt.Errorf("replace cache file: %w", err)
	}
	return nil
}

func (c Cache) filePath(source feed) string {
	family := "ipv4"
	if source.ipv6 {
		family = "ipv6"
	}
	return filepath.Join(c.Directory, fmt.Sprintf("%s-%s.json", strings.ToLower(source.country), family))
}
