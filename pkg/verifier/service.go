package verifier

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/bugsyhewitt/graverobber/pkg/finding"
)

// ServiceVerifier performs active, service-specific confirmation of CNAME
// takeover candidates for the three highest-signal services: AWS/S3, GitHub
// Pages, and Microsoft Azure (POST_V01 Rank 2).
//
// It only ever *upgrades* a finding from LIKELY to CONFIRMED — it never
// downgrades, and it never touches a finding the fingerprint stage already
// marked CONFIRMED (a definitive body-string match outranks a network probe).
// Probes are unauthenticated by default; a GitHub token may be supplied to
// raise the api.github.com rate limit from 60 to 5000 requests/hour. The tool
// remains credential-free unless the operator opts in.
//
// All probes are read-only. graverobber never attempts to claim a resource:
// the S3 check is a HEAD, the GitHub check is a repo-existence GET, and the
// Azure check is a DNS NXDOMAIN observation. Confirming a takeover is in scope;
// performing one is not.
type ServiceVerifier struct {
	client   *http.Client
	token    string
	nxLookup func(ctx context.Context, host string) (bool, error)
}

// Config configures a ServiceVerifier.
type Config struct {
	// GitHubToken, when non-empty, is sent as a Bearer credential on the
	// api.github.com probe to raise the per-hour rate limit.
	GitHubToken string
	// Timeout bounds each active probe. Zero selects a 10s default.
	Timeout time.Duration
	// Resolvers are the recursive DNS servers used for the Azure NXDOMAIN
	// check. Empty selects a sane public set.
	Resolvers []string
}

// NewServiceVerifier builds a ServiceVerifier from cfg. The returned verifier is
// ready to use; tests may override the unexported client/nxLookup fields to
// avoid real network I/O.
func NewServiceVerifier(cfg Config) *ServiceVerifier {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	sv := &ServiceVerifier{
		client: &http.Client{Timeout: timeout},
		token:  cfg.GitHubToken,
	}
	sv.nxLookup = newNXLookup(cfg.Resolvers, timeout)
	return sv
}

// compile-time interface check.
var _ Verifier = (*ServiceVerifier)(nil)

// Verify dispatches on f.Service. It returns f.Confidence unchanged for any
// vector other than CNAME, any service it does not handle, any finding already
// CONFIRMED, and any probe that fails or does not produce a confirming signal.
func (sv *ServiceVerifier) Verify(ctx context.Context, f finding.Finding) (finding.Confidence, error) {
	// Active verification only applies to CNAME findings: NS and SPF takeovers
	// are not probed over HTTP, and a definitive fingerprint match is already
	// CONFIRMED and must not be re-litigated by a probe.
	if f.Vector != finding.VectorCNAME || f.Confidence == finding.Confirmed {
		return f.Confidence, nil
	}

	switch f.Service {
	case "AWS/S3":
		return sv.verifyS3(ctx, f)
	case "GitHub Pages":
		return sv.verifyGitHubPages(ctx, f)
	case "Microsoft Azure":
		return sv.verifyAzure(ctx, f)
	default:
		return f.Confidence, nil
	}
}

// maxProbeBody caps how much of a probe response body we read. The signal
// strings (NoSuchBucket, etc.) appear in small XML/JSON error documents; a few
// KiB is ample and bounds memory against a hostile server.
const maxProbeBody = 8 << 10 // 8 KiB

// verifyS3 confirms a dangling S3 CNAME by probing the bucket's REST endpoint.
// A 404 carrying "NoSuchBucket" means the bucket is unclaimed and re-creatable.
func (sv *ServiceVerifier) verifyS3(ctx context.Context, f finding.Finding) (finding.Confidence, error) {
	bucket := s3Bucket(f.CNAME)
	if bucket == "" {
		return f.Confidence, nil
	}
	// Virtual-hosted–style endpoint. A HEAD omits the body, so issue a GET and
	// read a bounded prefix: the NoSuchBucket marker lives in the body.
	url := "https://" + bucket + ".s3.amazonaws.com/"
	status, body, err := sv.httpProbe(ctx, http.MethodGet, url, nil)
	if err != nil {
		return f.Confidence, nil // probe failed — keep fingerprint confidence
	}
	if status == http.StatusNotFound && strings.Contains(body, "NoSuchBucket") {
		return finding.Confirmed, nil
	}
	return f.Confidence, nil
}

// s3Bucket extracts the bucket name from a virtual-hosted S3 CNAME target such
// as "my-bucket.s3.amazonaws.com" or "my-bucket.s3-website-us-east-1.amazonaws.com".
// It returns "" when the target is not a recognisable S3 endpoint.
func s3Bucket(cname string) string {
	host := strings.TrimSuffix(strings.ToLower(cname), ".")
	// The bucket is everything before the first ".s3" label group.
	for _, marker := range []string{".s3.amazonaws.com", ".s3-website", ".s3."} {
		if i := strings.Index(host, marker); i > 0 {
			return host[:i]
		}
	}
	return ""
}

// verifyGitHubPages confirms a dangling GitHub Pages CNAME by asking the GitHub
// REST API whether the backing repository exists. A 404 means the repo is gone
// and the Pages name is claimable.
func (sv *ServiceVerifier) verifyGitHubPages(ctx context.Context, f finding.Finding) (finding.Confidence, error) {
	user, repo := githubUserRepo(f.CNAME)
	if user == "" {
		return f.Confidence, nil
	}
	hdr := http.Header{"Accept": {"application/vnd.github+json"}}
	if sv.token != "" {
		hdr.Set("Authorization", "Bearer "+sv.token)
	}
	url := "https://api.github.com/repos/" + user + "/" + repo
	status, _, err := sv.httpProbe(ctx, http.MethodGet, url, hdr)
	if err != nil {
		return f.Confidence, nil
	}
	if status == http.StatusNotFound {
		return finding.Confirmed, nil
	}
	return f.Confidence, nil
}

// githubUserRepo derives the owning user and the repository name from a
// "<user>.github.io" CNAME target. The canonical user-pages repository is
// "<user>.github.io"; probing that repo's existence is the standard
// claimability check. Returns ("","") for a non-github.io target.
func githubUserRepo(cname string) (user, repo string) {
	host := strings.TrimSuffix(strings.ToLower(cname), ".")
	const suffix = ".github.io"
	if !strings.HasSuffix(host, suffix) {
		return "", ""
	}
	user = strings.TrimSuffix(host, suffix)
	if user == "" || strings.Contains(user, ".") {
		// A custom-domain CNAME (e.g. "docs.github.io" is fine; "a.b.github.io"
		// is an org/project page whose repo we can't infer reliably). Restrict
		// to the unambiguous "<user>.github.io" → "<user>/<user>.github.io".
		if strings.Contains(user, ".") {
			return "", ""
		}
	}
	return user, host
}

// azureSuffixes are the Azure-owned DNS suffixes whose dangling CNAMEs the
// active NXDOMAIN check applies to.
var azureSuffixes = []string{
	"azurewebsites.net",
	"cloudapp.net",
	"cloudapp.azure.com",
	"trafficmanager.net",
	"blob.core.windows.net",
}

// verifyAzure confirms a dangling Azure CNAME by checking the target itself for
// NXDOMAIN. When the Azure resource group is deleted the provider stops
// answering for the hostname, so an NXDOMAIN on the azurewebsites.net (etc.)
// target is a strong claimability signal.
func (sv *ServiceVerifier) verifyAzure(ctx context.Context, f finding.Finding) (finding.Confidence, error) {
	if !hasAzureSuffix(f.CNAME) {
		return f.Confidence, nil
	}
	nx, err := sv.nxLookup(ctx, strings.TrimSuffix(strings.ToLower(f.CNAME), "."))
	if err != nil {
		return f.Confidence, nil
	}
	if nx {
		return finding.Confirmed, nil
	}
	return f.Confidence, nil
}

// hasAzureSuffix reports whether cname is under an Azure-owned DNS suffix.
func hasAzureSuffix(cname string) bool {
	host := strings.TrimSuffix(strings.ToLower(cname), ".")
	for _, s := range azureSuffixes {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

// httpProbe issues a single request and returns the status code and a bounded
// prefix of the response body. It is a thin wrapper so each service verifier
// shares identical context/timeout/body-cap handling.
func (sv *ServiceVerifier) httpProbe(ctx context.Context, method, url string, header http.Header) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return 0, "", err
	}
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := sv.client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProbeBody))
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(body), nil
}

// newNXLookup returns a DNS NXDOMAIN probe over the given recursive resolvers.
// It is built once per ServiceVerifier and closed over by verifyAzure so the
// hot path allocates no client. The returned func reports (true, nil) when the
// host resolves to NXDOMAIN, (false, nil) otherwise, and a non-nil error on
// transport failure (callers treat errors as "do not upgrade").
func newNXLookup(resolvers []string, timeout time.Duration) func(ctx context.Context, host string) (bool, error) {
	servers := effectiveResolvers(resolvers)
	client := &dns.Client{Timeout: timeout}
	return func(ctx context.Context, host string) (bool, error) {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(host), dns.TypeA)
		msg.RecursionDesired = true
		var lastErr error
		for _, server := range servers {
			resp, _, err := client.ExchangeContext(ctx, msg, server)
			if err != nil {
				lastErr = err
				continue
			}
			return resp.Rcode == dns.RcodeNameError, nil
		}
		if lastErr == nil {
			lastErr = errors.New("verifier: no resolvers available")
		}
		return false, lastErr
	}
}

// publicResolvers is the last-resort recursive resolver set, mirroring
// pkg/resolver's fallback so the Azure probe works without configuration.
var publicResolvers = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}

// effectiveResolvers normalises configured resolvers (adding :53 where absent)
// and falls back to the public set when none are configured.
func effectiveResolvers(resolvers []string) []string {
	if len(resolvers) == 0 {
		return publicResolvers
	}
	out := make([]string, len(resolvers))
	for i, s := range resolvers {
		if !strings.Contains(s, ":") {
			s += ":53"
		}
		out[i] = s
	}
	return out
}
