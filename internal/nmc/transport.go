package nmc

import (
	"context"
	"crypto/subtle"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// DefaultHTTPBind is the loopback address a Streamable HTTP server binds when no
// bind is configured (D9: never accidentally network-exposed).
const DefaultHTTPBind = "127.0.0.1:9876"

// RunStdio runs the stdio transport (D9 default). The SDK owns JSON-RPC framing
// over stdin/stdout; the only discipline required of the tool is D7 — keep every
// other byte off stdout — which New enforces for the default logger.
func (s *Server) RunStdio(ctx context.Context) error {
	return s.impl.Run(ctx, &mcp.StdioTransport{})
}

// isLoopback reports whether bind addresses only the loopback interface. A bare
// "localhost" or empty host counts as loopback; an explicit IP is loopback only
// when net.IP.IsLoopback agrees. A host that is neither (e.g. 0.0.0.0 or a LAN
// address) is treated as routable and triggers the D10 token requirement.
func isLoopback(bind string) bool {
	host, _, err := net.SplitHostPort(bind)
	if err != nil {
		host = bind
	}
	if host == "" || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// bearerAuth wraps next, rejecting any request whose Authorization header does
// not carry exactly the expected bearer token. The comparison is constant-time
// (crypto/subtle) so the endpoint does not leak token length or a prefix match
// through timing. This is the D10 enforcement for routable binds.
func bearerAuth(token string, next http.Handler) http.Handler {
	want := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := []byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if len(got) == 0 || subtle.ConstantTimeCompare(got, want) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RunHTTP runs the Streamable HTTP transport on bind. When bind is non-loopback
// it MUST carry a bearer token, or RunHTTP refuses to start (D10): an
// unauthenticated routable MCP endpoint exposing active tools is remote
// exploitation-as-a-service for anyone who finds the port. When token is
// non-empty the handler is wrapped in constant-time bearer auth even on loopback
// (defence in depth costs nothing here). The SDK's own DNS-rebinding protection
// remains in force.
//
// The server is shut down when ctx is cancelled.
func (s *Server) RunHTTP(ctx context.Context, bind, token string) error {
	// D10: a routable bind without a token is forbidden.
	if !isLoopback(bind) && token == "" {
		return errors.New("nmc: routable bind " + bind + " requires a bearer token (D10)")
	}

	handler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return s.impl },
		&mcp.StreamableHTTPOptions{
			// A 5-minute idle-session timeout reaps abandoned warehouse sessions
			// rather than leaking them; interactive use reconnects transparently.
			SessionTimeout: 5 * time.Minute,
		},
	)

	var h http.Handler = handler
	if token != "" {
		h = bearerAuth(token, handler) // D10
	}

	srv := &http.Server{
		Addr:              bind,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Shut the listener when the context is cancelled so RunHTTP returns and the
	// process can exit cleanly instead of blocking in ListenAndServe forever.
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	slog.Info("nmc http listening", "tool", s.name, "bind", bind, "auth", token != "")
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Run reads transport configuration from the environment (NMC_TRANSPORT,
// NMC_BIND, NMC_TOKEN) with command-line flags (--transport, --bind, --token)
// overriding it for interactive use, then dispatches to RunStdio (the default)
// or RunHTTP (D9). Flags are parsed leniently — an unknown flag the host passes
// (e.g. one the MCP launcher injects) does not abort startup.
func (s *Server) Run(ctx context.Context) error {
	transport := envOr("NMC_TRANSPORT", "stdio")
	bind := envOr("NMC_BIND", DefaultHTTPBind)
	token := os.Getenv("NMC_TOKEN")

	// Flags override env for interactive invocation. ContinueOnError + a discarded
	// parse error keeps an unexpected host-injected flag from killing the server;
	// the env-derived defaults still stand in that case.
	fs := flag.NewFlagSet(s.name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr) // never let flag usage text touch stdout (D7)
	fs.StringVar(&transport, "transport", transport, "transport: stdio|http")
	fs.StringVar(&bind, "bind", bind, "http bind address (loopback unless --token given)")
	fs.StringVar(&token, "token", token, "bearer token required for a routable http bind")
	_ = fs.Parse(os.Args[1:])

	if transport == "http" {
		return s.RunHTTP(ctx, bind, token)
	}
	return s.RunStdio(ctx)
}

// envOr returns the value of the named environment variable, or def when it is
// unset or empty.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
