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
	if err := CheckReady(); err != nil {
		t.Fatal(err)
	}

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
	if err := addRule(rules, name, addresses); err != nil {
		t.Fatal(err)
	}
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
	rule := found[name]
	if rule == nil {
		releaseRules(found)
		t.Fatalf("firewall rule %q was not found after creation", name)
	}
	matches, err := ruleMatches(rule, addresses)
	releaseRules(found)
	if err != nil {
		t.Fatalf("read back firewall rule %q: %v", name, err)
	}
	if !matches {
		t.Fatalf("firewall rule %q did not retain the expected settings", name)
	}

	if err := removeRule(); err != nil {
		t.Fatalf("remove test firewall rule %q: %v", name, err)
	}
	added = false
	found, err = findManagedRules(rules, name)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseRules(found)
	if found[name] != nil {
		t.Fatalf("firewall rule %q still exists after removal", name)
	}
}
