package nsproviders

// defaultProviders is the compiled-in snapshot of DNS providers whose deleted
// hosted zones are re-claimable. It mirrors the historical hardcoded list in
// pkg/detectors/ns.go and is the offline fallback when no cache is present.
//
// Source: github.com/indianajson/can-i-take-over-dns. Refresh the live list
// with `graverobber update --ns-providers`.
var defaultProviders = []Provider{
	{Suffix: "awsdns", Label: "AWS Route 53", Vulnerable: true},
	{Suffix: "googledomains.com", Label: "Google Cloud DNS", Vulnerable: true},
	{Suffix: "azure-dns.com", Label: "Azure DNS", Vulnerable: true},
	{Suffix: "azure-dns.net", Label: "Azure DNS", Vulnerable: true},
	{Suffix: "azure-dns.org", Label: "Azure DNS", Vulnerable: true},
	{Suffix: "azure-dns.info", Label: "Azure DNS", Vulnerable: true},
	{Suffix: "digitalocean.com", Label: "DigitalOcean", Vulnerable: true},
	{Suffix: "vultr.com", Label: "Vultr", Vulnerable: true},
	{Suffix: "linode.com", Label: "Linode", Vulnerable: true},
	{Suffix: "nsone.net", Label: "NS1", Vulnerable: true},
	{Suffix: "cloudflare.com", Label: "Cloudflare", Vulnerable: true},
	{Suffix: "dnsimple.com", Label: "DNSimple", Vulnerable: true},
	{Suffix: "dnsmadeeasy.com", Label: "DNS Made Easy", Vulnerable: true},
	{Suffix: "ultradns.net", Label: "UltraDNS", Vulnerable: true},
	{Suffix: "ultradns.com", Label: "UltraDNS", Vulnerable: true},
	{Suffix: "ultradns.org", Label: "UltraDNS", Vulnerable: true},
	{Suffix: "ultradns.biz", Label: "UltraDNS", Vulnerable: true},
	{Suffix: "dynect.net", Label: "Dyn", Vulnerable: true},
	{Suffix: "hurricane.net", Label: "Hurricane Electric", Vulnerable: true},
	{Suffix: "domaincontrol.com", Label: "GoDaddy", Vulnerable: true},
	{Suffix: "registrar-servers.com", Label: "Namecheap", Vulnerable: true},
	{Suffix: "name-services.com", Label: "Enom", Vulnerable: true},
}
