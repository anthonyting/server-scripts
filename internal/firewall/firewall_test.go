package firewall

import "testing"

func TestEqualAddressLists(t *testing.T) {
	if !equalAddressLists("192.0.2.0/24, 2001:db8::/32", "2001:DB8::/32,192.0.2.0/24") {
		t.Fatal("equalAddressLists() did not treat ordering and case as insignificant")
	}
	if equalAddressLists("192.0.2.0/24", "192.0.2.0/25") {
		t.Fatal("equalAddressLists() treated different CIDR sets as equal")
	}
}
