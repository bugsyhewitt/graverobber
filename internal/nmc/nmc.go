// Package nmc is the Go backend of the necromancer-mcp shared library: a thin,
// policy-applying adapter that turns any necromancer tool's existing engine into
// a Model Context Protocol (MCP) server with near-zero per-tool code.
//
// It is one of two language backends (the other is the Python necromancer_mcp
// package) behind a single conceptual three-function contract:
//
//   - New / AddTool   — register a tool on a policy-applied server (§4 D1, D5).
//   - Server.Finding  — emit a finding as structured content (§4.1, D8, D11).
//   - Server.Run      — run the configured transport (D7, D9, D10).
//
// The library is deliberately tiny. It is an adapter over the engine, never a
// reimplementation of it (D2/A1): a handler validates its input, calls the
// existing engine, and marshals the result into a Finding. No detection logic,
// payload tables, or network logic belong here or in any handler built on it.
//
// Design rules enforced or wired by this package (packet §3):
//
//	D5  tool names must match ^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$ with no run of
//	    repeated separators; AddTool panics at startup on a violation.
//	D6  active/exploitation paths must be opt-in per call; MustActive is the
//	    single chokepoint every active handler calls first.
//	D7  stdout is reserved for the JSON-RPC frame stream; New routes the default
//	    structured logger to stderr so no diagnostic byte can corrupt framing.
//	D8  findings are returned as typed structs so the SDK emits structuredContent.
//	D9  transport is configuration (stdio default, Streamable HTTP optional).
//	D10 a routable HTTP bind requires a bearer token; RunHTTP refuses otherwise.
//	D11 every server advertises Name+Version and every finding carries the tool,
//	    version, verb, and whether an active path was used.
package nmc

import (
	"context"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// SchemaID is the interim finding schema marker (§4.1). Packet 03 bumps this to
// the canonical suite schema id and adds fields; tools emitting this shape today
// validate against the canonical schema tomorrow with zero handler changes, so
// the constant is the single forward-compatibility seam.
const SchemaID = "nmc.finding/v0"

// Finding states (§4.1). A finding's State is required and must be one of these.
const (
	StateDetected      = "detected"       // a candidate issue was found (safe verbs)
	StateConfirmed     = "confirmed"      // a candidate was actively proven real
	StateNotVulnerable = "not_vulnerable" // engine ran; target is not affected
	StateError         = "error"          // the target interaction failed (Appendix D)
)

// nameRE is the D5 tool-name grammar: lowercase letters, digits, underscore and
// hyphen, no leading or trailing separator. A separate check (see validName)
// additionally rejects any run of repeated separators (`__`, `--`, `-_`) to keep
// names clean, per the §13 A4 / Appendix B.2 decision to ban double separators.
var nameRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$`)

// doubleSepRE matches two or more consecutive separator characters anywhere in a
// name (e.g. the `__` in `scan__2`). The base nameRE permits these; banning them
// is a deliberate, tested policy choice (Appendix B.2).
var doubleSepRE = regexp.MustCompile(`[_-]{2,}`)

// validName reports whether name satisfies the full D5 policy: it matches the
// base grammar AND contains no run of repeated separators.
func validName(name string) bool {
	return nameRE.MatchString(name) && !doubleSepRE.MatchString(name)
}

// Finding is the interim structured-output record (§4.1), forward-compatible
// with the Packet 03 canonical schema (additive fields only; never remove or
// repurpose a field). State and Target are required; everything else is optional.
//
// Evidence MUST be bounded (§9/A5): never stream a whole file, response body, or
// schema into it — truncate to a signal-bearing snippet and put bulk detail
// behind Raw. The JSON-RPC channel is a control plane, not a file transfer.
type Finding struct {
	Schema      string         `json:"schema"`
	Tool        string         `json:"tool"`
	ToolVersion string         `json:"tool_version"`
	Verb        string         `json:"verb"`
	Active      bool           `json:"active"`
	Target      string         `json:"target"`
	Surface     string         `json:"surface,omitempty"`
	State       string         `json:"state"` // detected|confirmed|not_vulnerable|error
	Severity    *string        `json:"severity,omitempty"`
	Title       string         `json:"title,omitempty"`
	Evidence    string         `json:"evidence,omitempty"`
	Refs        []string       `json:"refs,omitempty"`
	Raw         map[string]any `json:"raw,omitempty"`
	TS          string         `json:"ts"`
}

// Server wraps the SDK server and applies suite policy: D5 naming enforcement on
// registration, D7 stderr-only logging, and Finding construction with the
// schema/tool/version/timestamp pre-filled (D11). A tool author touches only the
// small public surface; the SDK server is private so policy cannot be bypassed.
type Server struct {
	name    string
	version string
	impl    *mcp.Server
}

// New builds a policy-applied server. It routes the default structured logger to
// stderr (D7) so that no log line, banner, or diagnostic can ever land on stdout
// and corrupt the JSON-RPC frame stream — the single dominant failure mode for
// stdio MCP servers (§2/A2). name is the tool's bare name (no gh0ul- prefix, D5);
// version tracks the tool's semver (D11).
func New(name, version string) *Server {
	// D7: every diagnostic byte goes to stderr; stdout is the JSON-RPC channel.
	// We set the process-wide default so a handler that reaches for slog without
	// threading a logger still cannot contaminate stdout.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	return &Server{
		name:    name,
		version: version,
		impl: mcp.NewServer(&mcp.Implementation{
			Name:    name,
			Version: version,
		}, nil),
	}
}

// Name returns the server's advertised name (the bare tool name).
func (s *Server) Name() string { return s.name }

// Version returns the server's advertised version.
func (s *Server) Version() string { return s.version }

// MCP exposes the wrapped SDK server for advanced wiring a tool may need that the
// thin contract does not cover (e.g. AddResource for read-only reference data,
// Appendix E). Tools should prefer AddTool and the Finding/Run helpers; reach for
// this only for capabilities the policy layer deliberately does not wrap.
func (s *Server) MCP() *mcp.Server { return s.impl }

// AddResource registers a read-only MCP resource (Appendix E). Resources are for
// data (a fingerprint DB, a wordlist), never for actions or anything that touches
// a target — those are tools. This is a thin pass-through to the SDK; resource URIs
// are not subject to the D5 tool-name grammar.
func (s *Server) AddResource(uri, name, desc, mimeType string, handler func() (string, error)) {
	s.impl.AddResource(
		&mcp.Resource{URI: uri, Name: name, Description: desc, MIMEType: mimeType},
		func(_ context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			body, err := handler()
			if err != nil {
				return nil, err
			}
			return &mcp.ReadResourceResult{
				Contents: []*mcp.ResourceContents{{
					URI:      uri,
					MIMEType: mimeType,
					Text:     body,
				}},
			}, nil
		},
	)
}

// AddTool registers a typed tool on the server, enforcing the D5 name policy.
//
// It panics at process startup — never at request time — if name is not a legal
// MCP tool name, so a misnamed tool fails the operator immediately and loudly
// (A4) rather than surfacing a baffling error to an agent mid-session. The
// handler signature mirrors the SDK's typed generics: In and Out are inferred
// from JSON-tagged structs and drive the tool's input/output JSON Schema, so the
// SDK emits Out as structuredContent (D8).
//
// AddTool is a free function rather than a method because Go methods cannot carry
// their own type parameters; the server is threaded as the first argument exactly
// as the official SDK's mcp.AddTool does.
func AddTool[In, Out any](s *Server, name, desc string,
	handler mcp.ToolHandlerFor[In, Out]) {
	if !validName(name) {
		// D5/A4: fail fast at process start. A bad-but-legal name (e.g. a numeric
		// _2 disambiguator) is not caught here — that is a review concern — but a
		// structurally illegal one never reaches a client.
		panic("nmc: illegal MCP tool name " + name + " (must match " + nameRE.String() + " with no repeated separators)")
	}
	mcp.AddTool(s.impl, &mcp.Tool{Name: name, Description: desc}, handler)
}

// Finding constructs a Finding with the Schema, Tool, ToolVersion, and TS
// (RFC3339 UTC) pre-filled (D11). The caller supplies the four required-by-policy
// fields — verb, target, state, and whether an active path was used — and then
// sets any optional fields (Surface, Title, Evidence, Refs, Raw) directly on the
// returned value before emitting it.
func (s *Server) Finding(verb, target, state string, active bool) Finding {
	return Finding{
		Schema:      SchemaID,
		Tool:        s.name,
		ToolVersion: s.version,
		Verb:        verb,
		Target:      target,
		State:       state,
		Active:      active,
		TS:          time.Now().UTC().Format(time.RFC3339),
	}
}

// RedactSecret reduces a credential-like value to its first four characters plus
// a length suffix (e.g. "AKIA…[len=20]"), so a handler that must reference a
// secret in Evidence or a log never echoes the live value into the channel or to
// stderr (§10 secret hygiene). An empty input yields an empty string; a value of
// four characters or fewer is replaced entirely by its length marker so nothing
// recoverable leaks.
func RedactSecret(v string) string {
	if v == "" {
		return ""
	}
	r := []rune(v)
	if len(r) <= 4 {
		return strings.Repeat("•", len(r)) + "[len=" + itoa(len(r)) + "]"
	}
	return string(r[:4]) + "…[len=" + itoa(len(r)) + "]"
}

// itoa is a tiny dependency-free integer formatter for RedactSecret's length
// suffix, kept local so the package's only non-stdlib import remains the SDK.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
