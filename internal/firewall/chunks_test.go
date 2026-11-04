package firewall

import (
	"errors"
	"strings"
	"testing"

	ole "github.com/go-ole/go-ole"
)

func TestSplitAddressListsByCount(t *testing.T) {
	addresses := make([]string, maxAddressesPerRule+1)
	for i := range addresses {
		addresses[i] = "192.0.2.0/24"
	}

	chunks, err := splitAddressLists(addresses)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 2 {
		t.Fatalf("got %d chunks, want 2", len(chunks))
	}
	if got := strings.Count(chunks[0], ",") + 1; got != maxAddressesPerRule {
		t.Fatalf("first chunk has %d addresses, want %d", got, maxAddressesPerRule)
	}
	if got := strings.Count(chunks[1], ",") + 1; got != 1 {
		t.Fatalf("second chunk has %d addresses, want 1", got)
	}
}

func TestSplitAddressListsBySize(t *testing.T) {
	addresses := []string{
		strings.Repeat("a", maxAddressListByteCount-1),
		"b",
	}

	chunks, err := splitAddressLists(addresses)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 2 || len(chunks[0]) != maxAddressListByteCount-1 || chunks[1] != "b" {
		t.Fatalf("unexpected chunks: lengths %v", chunkLengths(chunks))
	}
}

func TestSplitAddressListsRejectsInvalidInput(t *testing.T) {
	tests := [][]string{
		nil,
		{""},
		{"192.0.2.0/24,198.51.100.0/24"},
		{strings.Repeat("a", maxAddressListByteCount+1)},
	}
	for _, addresses := range tests {
		if _, err := splitAddressLists(addresses); err == nil {
			t.Errorf("splitAddressLists(%v) succeeded; want an error", addresses)
		}
	}
}

func TestHasHRESULTFindsNestedCOMError(t *testing.T) {
	err := ole.NewErrorWithSubError(
		0x80020009,
		"Exception occurred.",
		errors.New("scode: 0x80070005"),
	)
	if !hasHRESULT(err, 0x80020009) {
		t.Fatal("hasHRESULT() missed the outer COM error")
	}
	if !hasHRESULT(err, 0x80070005) {
		t.Fatal("hasHRESULT() missed the nested HRESULT")
	}
	if isAccessDenied(err) != true {
		t.Fatal("isAccessDenied() missed nested E_ACCESSDENIED")
	}
	if hasHRESULT(err, 0x800706c6) {
		t.Fatal("hasHRESULT() reported an absent HRESULT")
	}
}

func chunkLengths(chunks []string) []int {
	lengths := make([]int, len(chunks))
	for i, chunk := range chunks {
		lengths[i] = len(chunk)
	}
	return lengths
}
