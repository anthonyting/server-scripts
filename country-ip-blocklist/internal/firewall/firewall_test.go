package firewall

import "testing"

func TestEqualAddressLists(t *testing.T) {
	if !equalAddressLists("192.0.2.0/24, 2001:db8::/32", "2001:DB8::/32,192.0.2.0/24") {
		t.Fatal("equalAddressLists() did not treat ordering and case as insignificant")
	}
	if !equalAddressLists("192.0.2.1", "192.0.2.1/32") {
		t.Fatal("equalAddressLists() did not treat an IPv4 host address and /32 as equivalent")
	}
	if !equalAddressLists("192.0.2.1/255.255.255.255", "192.0.2.1/32") {
		t.Fatal("equalAddressLists() did not treat a dotted IPv4 mask and prefix length as equivalent")
	}
	if !equalAddressLists("192.0.2.0/255.255.255.0", "192.0.2.0/24") {
		t.Fatal("equalAddressLists() did not normalize a dotted IPv4 subnet mask")
	}
	if !equalAddressLists("2001:db8::1", "2001:db8::1/128") {
		t.Fatal("equalAddressLists() did not treat an IPv6 host address and /128 as equivalent")
	}
	if equalAddressLists("192.0.2.0/24", "192.0.2.0/25") {
		t.Fatal("equalAddressLists() treated different CIDR sets as equal")
	}
}
