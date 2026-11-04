package ipdeny

import (
	"net/netip"
	"sort"
)

// Merge masks, removes contained ranges, and combines adjacent sibling CIDRs.
func Merge(prefixes []netip.Prefix) []netip.Prefix {
	canonical := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		if prefix.IsValid() {
			canonical = append(canonical, prefix.Masked())
		}
	}
	sort.Slice(canonical, func(i, j int) bool {
		left, right := canonical[i], canonical[j]
		if comparison := left.Addr().Compare(right.Addr()); comparison != 0 {
			return comparison < 0
		}
		return left.Bits() < right.Bits()
	})

	merged := make([]netip.Prefix, 0, len(canonical))
	for _, prefix := range canonical {
		if len(merged) > 0 && merged[len(merged)-1].Contains(prefix.Addr()) {
			continue
		}
		merged = append(merged, prefix)
		for len(merged) >= 2 {
			last := len(merged) - 1
			parent, ok := mergeSiblings(merged[last-1], merged[last])
			if !ok {
				break
			}
			merged = merged[:last-1]
			if len(merged) > 0 && merged[len(merged)-1].Contains(parent.Addr()) {
				break
			}
			merged = append(merged, parent)
		}
	}
	return merged
}

func mergeSiblings(left, right netip.Prefix) (netip.Prefix, bool) {
	if left.Bits() == 0 || left.Bits() != right.Bits() ||
		left.Addr().BitLen() != right.Addr().BitLen() {
		return netip.Prefix{}, false
	}
	leftParent := netip.PrefixFrom(left.Addr(), left.Bits()-1).Masked()
	rightParent := netip.PrefixFrom(right.Addr(), right.Bits()-1).Masked()
	if leftParent != rightParent || left.Addr() == right.Addr() {
		return netip.Prefix{}, false
	}
	return leftParent, true
}
