package firewall

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sort"
	"strconv"
	"strings"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"
)

const (
	managedDescription      = "Managed by country-ip-blocklist."
	managedGrouping         = "Country IP Blocklist"
	allProfiles             = int32(0x7fffffff)
	maxAddressesPerRule     = 10_000
	maxAddressListByteCount = 256 * 1024
)

// CheckReady verifies that the process is elevated and local firewall rules
// are not disabled by Group Policy.
func CheckReady() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("firewall changes require an elevated administrator process; rerun from an Administrator terminal")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED); err != nil {
		return fmt.Errorf("initialize Windows COM: %w", err)
	}
	defer ole.CoUninitialize()

	policy, err := createDispatch("HNetCfg.FwPolicy2")
	if err != nil {
		return fmt.Errorf("create Windows Firewall policy COM object: %w", err)
	}
	defer policy.Release()

	result, err := oleutil.GetProperty(policy, "LocalPolicyModifyState")
	if err != nil {
		return fmt.Errorf("check whether local firewall rules are allowed: %w", err)
	}
	defer result.Clear()
	state, ok := result.Value().(int32)
	if !ok {
		return fmt.Errorf("Windows Firewall returned unexpected local-policy state %T", result.Value())
	}
	switch state {
	case 0:
		return nil
	case 1:
		return errors.New("Group Policy overrides local firewall rules; enable local rule merging in the effective Windows Defender Firewall policy")
	case 2:
		return errors.New("Windows Firewall reports inbound traffic blocked for the active profile; verify the profile's Block all incoming connections setting")
	default:
		return fmt.Errorf("Windows Firewall returned unknown local-policy state %d", state)
	}
}

// Apply creates or updates the managed rule set with the provided remote ranges.
func Apply(ruleName string, prefixes []netip.Prefix) error {
	if len(prefixes) == 0 {
		return errors.New("refusing to apply an empty firewall address list")
	}
	remoteAddresses := make([]string, len(prefixes))
	for i, prefix := range prefixes {
		if !prefix.IsValid() {
			return fmt.Errorf("invalid firewall prefix at index %d", i)
		}
		remoteAddresses[i] = prefix.Masked().String()
	}
	sort.Strings(remoteAddresses)
	chunks, err := splitAddressLists(remoteAddresses)
	if err != nil {
		return err
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED); err != nil {
		return fmt.Errorf("initialize Windows COM: %w", err)
	}
	defer ole.CoUninitialize()

	policy, err := createDispatch("HNetCfg.FwPolicy2")
	if err != nil {
		return fmt.Errorf("create Windows Firewall policy COM object: %w", err)
	}
	defer policy.Release()

	rulesValue, err := oleutil.GetProperty(policy, "Rules")
	if err != nil {
		return fmt.Errorf("get Windows Firewall rules: %w", err)
	}
	defer rulesValue.Clear()
	rules := rulesValue.ToIDispatch()
	if rules == nil {
		return errors.New("Windows Firewall returned an invalid rules collection")
	}

	existingRules, err := findManagedRules(rules, ruleName)
	if err != nil {
		return err
	}
	defer releaseRules(existingRules)

	for i, addresses := range chunks {
		name := fmt.Sprintf("%s-%03d", ruleName, i+1)
		if err := ensureRule(rules, existingRules[name], name, addresses); err != nil {
			return err
		}
	}
	if err := removeObsoleteRules(rules, existingRules, ruleName, len(chunks)); err != nil {
		return err
	}
	fmt.Printf("Applied %d managed inbound block rules.\n", len(chunks))
	return nil
}

func createDispatch(programID string) (*ole.IDispatch, error) {
	unknown, err := oleutil.CreateObject(programID)
	if err != nil {
		return nil, err
	}
	defer unknown.Release()
	return unknown.QueryInterface(ole.IID_IDispatch)
}

func ensureRule(rules, existing *ole.IDispatch, name, addresses string) error {
	if existing != nil {
		description, err := stringProperty(existing, "Description")
		if err != nil {
			return fmt.Errorf("read description of rule %q: %w", name, err)
		}
		if description != managedDescription {
			return fmt.Errorf("rule %q already exists and is not owned by country-ip-blocklist; refusing to modify it", name)
		}
		if matches, err := ruleMatches(existing, addresses); err != nil {
			return fmt.Errorf("inspect existing rule %q: %w", name, err)
		} else if matches {
			fmt.Printf("Rule %q already matches.\n", name)
			return nil
		}
	}
	return addRule(rules, name, addresses)
}

func findManagedRules(rules *ole.IDispatch, ruleName string) (map[string]*ole.IDispatch, error) {
	found := make(map[string]*ole.IDispatch)
	err := oleutil.ForEach(rules, func(value *ole.VARIANT) error {
		defer value.Clear()
		candidate := value.ToIDispatch()
		if candidate == nil {
			return errors.New("Windows Firewall returned a rule without an IDispatch interface")
		}
		candidateName, err := stringProperty(candidate, "Name")
		if err != nil {
			return fmt.Errorf("read firewall rule name: %w", err)
		}
		if candidateName != ruleName && !strings.HasPrefix(candidateName, ruleName+"-") {
			return nil
		}
		if _, exists := found[candidateName]; exists {
			return fmt.Errorf("multiple Windows Firewall rules have the name %q", candidateName)
		}
		candidate.AddRef()
		found[candidateName] = candidate
		return nil
	})
	if err != nil {
		releaseRules(found)
		return nil, fmt.Errorf("enumerate Windows Firewall rules: %w", err)
	}
	return found, nil
}

func releaseRules(rules map[string]*ole.IDispatch) {
	for _, rule := range rules {
		rule.Release()
	}
}

func ruleMatches(rule *ole.IDispatch, addresses string) (bool, error) {
	description, err := stringProperty(rule, "Description")
	if err != nil || description != managedDescription {
		return false, err
	}
	properties := []struct {
		name  string
		value any
	}{
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
		matches, err := propertyMatches(rule, property.name, property.value)
		if err != nil || !matches {
			return false, err
		}
	}
	return true, nil
}

func addRule(rules *ole.IDispatch, name, addresses string) error {
	rule, err := createDispatch("HNetCfg.FWRule")
	if err != nil {
		return fmt.Errorf("create firewall rule COM object: %w", err)
	}
	defer rule.Release()

	properties := []struct {
		name  string
		value any
	}{
		{name: "Name", value: name},
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
		if err := putProperty(rule, property.name, property.value); err != nil {
			return fmt.Errorf("set %s on new rule %q: %w", property.name, name, err)
		}
	}

	result, err := oleutil.CallMethod(rules, "Add", rule)
	if err != nil {
		details := fmt.Sprintf("add firewall rule %q (%d CIDRs, %d characters): %v",
			name, strings.Count(addresses, ",")+1, len(addresses), describeCOMError(err))
		if isAccessDenied(err) {
			details += "; run from an elevated administrator process and check that Group Policy permits local firewall rule merging"
		}
		return errors.New(details)
	}
	if result != nil {
		defer result.Clear()
	}
	fmt.Printf("Created inbound block rule %q.\n", name)
	return nil
}

func removeObsoleteRules(rules *ole.IDispatch, existing map[string]*ole.IDispatch, ruleName string, chunkCount int) error {
	var obsolete []string
	for name, candidate := range existing {
		description, err := stringProperty(candidate, "Description")
		if err != nil {
			return fmt.Errorf("read description of rule %q: %w", name, err)
		}
		if description != managedDescription {
			continue
		}
		if name == ruleName {
			obsolete = append(obsolete, name)
			continue
		}
		index, err := strconv.Atoi(strings.TrimPrefix(name, ruleName+"-"))
		if err != nil || index < 1 || index > chunkCount || fmt.Sprintf("%s-%03d", ruleName, index) != name {
			obsolete = append(obsolete, name)
		}
	}
	sort.Strings(obsolete)
	for _, name := range obsolete {
		result, err := oleutil.CallMethod(rules, "Remove", name)
		if result != nil {
			result.Clear()
		}
		if err != nil {
			return fmt.Errorf("remove obsolete firewall rule %q: %w", name, describeCOMError(err))
		}
	}
	return nil
}

func splitAddressLists(addresses []string) ([]string, error) {
	if len(addresses) == 0 {
		return nil, errors.New("refusing to apply an empty firewall address list")
	}
	var chunks []string
	var current strings.Builder
	count := 0
	for _, address := range addresses {
		if address == "" || strings.ContainsAny(address, ",\r\n") {
			return nil, fmt.Errorf("invalid firewall address %q", address)
		}
		additionalBytes := len(address)
		if count > 0 {
			additionalBytes++
		}
		if additionalBytes > maxAddressListByteCount {
			return nil, fmt.Errorf("firewall address %q exceeds the maximum rule address-list size", address)
		}
		if count > 0 && (count >= maxAddressesPerRule || current.Len()+additionalBytes > maxAddressListByteCount) {
			chunks = append(chunks, current.String())
			current.Reset()
			count = 0
			additionalBytes = len(address)
		}
		if count > 0 {
			current.WriteByte(',')
		}
		current.WriteString(address)
		count++
	}
	chunks = append(chunks, current.String())
	return chunks, nil
}

func propertyMatches(dispatch *ole.IDispatch, name string, want any) (bool, error) {
	result, err := oleutil.GetProperty(dispatch, name)
	if err != nil {
		return false, err
	}
	defer result.Clear()
	return propertyValueMatches(name, result.Value(), want)
}

func propertyValueMatches(name string, value, want any) (bool, error) {
	switch expected := want.(type) {
	case string:
		actual, ok := value.(string)
		if !ok {
			return false, nil
		}
		if name == "LocalAddresses" || name == "RemoteAddresses" {
			return equalAddressLists(actual, expected), nil
		}
		return actual == expected, nil
	case bool:
		actual, ok := value.(bool)
		return ok && actual == expected, nil
	case int32:
		actual, ok := value.(int32)
		return ok && actual == expected, nil
	default:
		return false, fmt.Errorf("unsupported firewall property type %T", want)
	}
}

func equalAddressLists(current, desired string) bool {
	currentSet := make(map[string]struct{})
	for _, address := range strings.Split(current, ",") {
		address = strings.TrimSpace(address)
		if address != "" {
			currentSet[normalizeFirewallAddress(address)] = struct{}{}
		}
	}
	desiredSet := make(map[string]struct{})
	for _, address := range strings.Split(desired, ",") {
		address = strings.TrimSpace(address)
		if address != "" {
			desiredSet[normalizeFirewallAddress(address)] = struct{}{}
		}
	}
	if len(currentSet) != len(desiredSet) {
		return false
	}
	for address := range desiredSet {
		if _, ok := currentSet[address]; !ok {
			return false
		}
	}
	return true
}

func normalizeFirewallAddress(address string) string {
	if prefix, err := netip.ParsePrefix(address); err == nil {
		return prefix.Masked().String()
	}
	if addrText, maskText, ok := strings.Cut(address, "/"); ok {
		addr, addrErr := netip.ParseAddr(addrText)
		mask, maskErr := netip.ParseAddr(maskText)
		if addrErr == nil && maskErr == nil && addr.Is4() && mask.Is4() {
			maskBytes := mask.As4()
			ones, bits := net.IPMask(maskBytes[:]).Size()
			if bits == 32 {
				return netip.PrefixFrom(addr, ones).Masked().String()
			}
		}
	}
	if addr, err := netip.ParseAddr(address); err == nil {
		return netip.PrefixFrom(addr, addr.BitLen()).String()
	}
	return strings.ToLower(address)
}

func stringProperty(dispatch *ole.IDispatch, name string) (string, error) {
	result, err := oleutil.GetProperty(dispatch, name)
	if err != nil {
		return "", err
	}
	defer result.Clear()
	value, ok := result.Value().(string)
	if !ok {
		return "", fmt.Errorf("property has unexpected type %T", result.Value())
	}
	return value, nil
}

func putProperty(dispatch *ole.IDispatch, name string, value any) error {
	result, err := oleutil.PutProperty(dispatch, name, value)
	if result != nil {
		defer result.Clear()
	}
	return err
}

func isAccessDenied(err error) bool {
	return hasHRESULT(err, 0x80070005)
}

func describeCOMError(err error) error {
	details := err.Error()
	switch {
	case hasHRESULT(err, 0x80070005):
		details += "; Windows Firewall denied access (E_ACCESSDENIED)"
	case hasHRESULT(err, 0x800706c6):
		details += "; Windows rejected the COM array bounds (RPC_S_INVALID_BOUND); reduce the per-rule CIDR chunk size"
	}
	return errors.New(details)
}

func hasHRESULT(err error, code uint32) bool {
	wanted := fmt.Sprintf("0x%08x", code)
	for current := err; current != nil; current = errors.Unwrap(current) {
		if comErr, ok := current.(*ole.OleError); ok && uint32(comErr.Code()) == code {
			return true
		}
		if strings.Contains(strings.ToLower(current.Error()), wanted) {
			return true
		}
	}
	return false
}
