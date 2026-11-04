package firewall

import (
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

func TestWindowsFirewallRuleLifecycle(t *testing.T) {
	if os.Getenv("COUNTRY_IP_BLOCKLIST_FIREWALL_INTEGRATION") != "1" {
		t.Skip("set COUNTRY_IP_BLOCKLIST_FIREWALL_INTEGRATION=1 to modify Windows Firewall")
	}
	t.Log("checking elevation and local firewall policy")
	if err := CheckReady(); err != nil {
		t.Fatal(err)
	}
	t.Log("elevation and local firewall policy check passed")

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED); err != nil {
		t.Fatalf("initialize Windows COM: %v", err)
	}
	defer ole.CoUninitialize()

	policy, err := createDispatch("HNetCfg.FwPolicy2")
	if err != nil {
		t.Fatalf("create Windows Firewall policy COM object: %v", err)
	}
	defer policy.Release()

	rulesValue, err := oleutil.GetProperty(policy, "Rules")
	if err != nil {
		t.Fatalf("get Windows Firewall rules: %v", err)
	}
	defer rulesValue.Clear()
	rules := rulesValue.ToIDispatch()
	if rules == nil {
		t.Fatal("Windows Firewall returned an invalid rules collection")
	}

	name := fmt.Sprintf("CountryIPBlocklist-CI-%d", time.Now().UnixNano())
	addresses := "192.0.2.1/32"
	t.Logf("creating temporary inbound block rule %q with remote addresses %q", name, addresses)
	if err := addRule(rules, name, addresses); err != nil {
		t.Fatal(err)
	}
	t.Logf("created temporary rule %q", name)
	added := true
	removeRule := func() error {
		result, err := oleutil.CallMethod(rules, "Remove", name)
		if result != nil {
			result.Clear()
		}
		return err
	}
	defer func() {
		if added {
			if err := removeRule(); err != nil {
				t.Errorf("remove test firewall rule %q during cleanup: %v", name, err)
			}
		}
	}()

	found, err := findManagedRules(rules, name)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseRules(found)
	rule := found[name]
	if rule == nil {
		t.Fatalf("firewall rule %q was not found after creation", name)
	}
	properties := []struct {
		name  string
		value any
	}{
		{name: "Description", value: managedDescription},
		{name: "Grouping", value: managedGrouping},
		{name: "Direction", value: int32(1)},
		{name: "Action", value: int32(0)},
		{name: "Enabled", value: true},
		{name: "Profiles", value: allProfiles},
		{name: "Protocol", value: int32(256)},
		{name: "LocalAddresses", value: "*"},
		{name: "RemoteAddresses", value: addresses},
	}
	for _, property := range properties {
		result, propertyErr := oleutil.GetProperty(rule, property.name)
		if propertyErr != nil {
			t.Fatalf("read back firewall rule %q property %q (expected %#v): %v",
				name, property.name, property.value, propertyErr)
		}
		actual := result.Value()
		result.Clear()
		match, propertyErr := propertyValueMatches(property.name, actual, property.value)
		if propertyErr != nil {
			t.Fatalf("compare firewall rule %q property %q: %v", name, property.name, propertyErr)
		}
		if !match {
			t.Fatalf("firewall rule %q property %q mismatch: got %#v (%T), want %#v (%T)",
				name, property.name, actual, actual, property.value, property.value)
		}
		t.Logf("verified property %s: got %#v", property.name, actual)
	}

	t.Logf("removing temporary rule %q", name)
	if err := removeRule(); err != nil {
		t.Fatalf("remove test firewall rule %q: %v", name, err)
	}
	added = false
	t.Logf("removed temporary rule %q; verifying it is absent", name)
	found, err = findManagedRules(rules, name)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseRules(found)
	if found[name] != nil {
		t.Fatalf("firewall rule %q still exists after removal", name)
	}
	t.Logf("confirmed temporary rule %q is absent", name)
}
