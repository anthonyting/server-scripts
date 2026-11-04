# Country IP Blocklist

A Go updater for one Windows Firewall rule built from IPdeny country CIDR
feeds. It defaults to China, Russia, Taiwan, Ukraine, and Nigeria and includes
both IPv4 and IPv6. The code separates command-line handling, IPdeny feed
fetching and CIDR merging, and the Windows Firewall integration.

The updater fetches every requested feed before touching the firewall. It
rejects failed, empty, malformed, or wrong-family feeds; masks, deduplicates,
and merges overlapping or adjacent CIDRs; then updates a small set of persistent
inbound block rules through Windows Firewall's COM API. Address lists are split
at 10,000 CIDRs or 256 KiB per rule. It does not launch PowerShell.
Unchanged rules are left alone, and obsolete managed rules are removed only
after the desired set is applied. Failed downloads never replace the last
applied firewall policy.
Validated feed files are cached under the current account's cache directory for
15 minutes by default, preventing rapid reruns from repeatedly downloading the
same lists. Use `-cache-ttl` to change the lifetime or set it to `0` to disable
the cache; `-cache-dir` overrides the cache location.

## Build and run

Build on Windows with Go 1.22 or newer:

```powershell
go test ./...
go build -o country-ip-blocklist.exe ./cmd/country-ip-blocklist
```

Preview the fetched and merged feed sizes without changing the firewall:

```powershell
.\country-ip-blocklist.exe -dry-run
```

Apply the policy from an elevated PowerShell or an elevated scheduled task:

```powershell
.\country-ip-blocklist.exe
```

The default rule name is `CountryIPBlocklist`. The updater will create that
rule if absent, update it only if its description identifies it as managed by
this program, and refuse to take over an unrelated rule with the same name.
This rule blocks all inbound ports on all profiles. To change the countries,
use `-countries CN,RU,TW,UA,NG`; to omit IPv6, use `-ipv6=false`. A scheduled
task can run the executable periodically under an account with permission to
modify the persistent firewall policy.

IPdeny feeds are downloaded from:

- `https://www.ipdeny.com/ipblocks/data/countries/{country}.zone`
- `https://www.ipdeny.com/ipv6/ipaddresses/blocks/{country}.zone`

Country IP allocation is approximate and can block legitimate users. Review
the selected countries and test the policy before relying on it in production.
