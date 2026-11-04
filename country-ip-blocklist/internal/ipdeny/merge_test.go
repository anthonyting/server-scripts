package ipdeny

import (
	"net/netip"
	"testing"
)

func TestMerge(t *testing.T) {
	input := []netip.Prefix{
		mustPrefix(t, "192.0.2.0/25"),
		mustPrefix(t, "192.0.2.128/25"),
		mustPrefix(t, "192.0.2.0/24"),
		mustPrefix(t, "2001:db8::/33"),
		mustPrefix(t, "2001:db8:8000::/33"),
		mustPrefix(t, "198.51.100.0/24"),
	}
	want := []netip.Prefix{
		mustPrefix(t, "192.0.2.0/24"),
		mustPrefix(t, "198.51.100.0/24"),
		mustPrefix(t, "2001:db8::/32"),
	}

	if got := Merge(input); !equalPrefixes(got, want) {
		t.Fatalf("Merge() = %v, want %v", got, want)
	}
}
