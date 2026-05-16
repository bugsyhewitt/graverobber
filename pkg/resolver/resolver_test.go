package resolver

import (
	"errors"
	"testing"
	"time"
)

func TestNew_Defaults(t *testing.T) {
	r := New(nil, 0)
	if r == nil {
		t.Fatal("New returned nil")
	}
	if r.Timeout() != 5*time.Second {
		t.Errorf("expected default timeout 5s, got %v", r.Timeout())
	}
	if len(r.Servers()) != 0 {
		t.Errorf("expected empty servers slice, got %v", r.Servers())
	}
}

func TestNew_ConfiguredTimeout(t *testing.T) {
	r := New(nil, 3*time.Second)
	if r.Timeout() != 3*time.Second {
		t.Errorf("expected 3s, got %v", r.Timeout())
	}
}

func TestNew_Servers(t *testing.T) {
	r := New([]string{"1.2.3.4", "5.6.7.8:5353"}, 5*time.Second)
	if len(r.Servers()) != 2 {
		t.Fatalf("expected 2 servers, got %v", r.Servers())
	}
}

func TestEffectiveServers_NormalizesPort(t *testing.T) {
	r := New([]string{"8.8.8.8"}, 5*time.Second)
	servers := r.effectiveServers()
	if len(servers) == 0 {
		t.Fatal("expected at least one effective server")
	}
	// With "8.8.8.8" as input (no port), effectiveServers adds ":53".
	if servers[0] != "8.8.8.8:53" {
		t.Errorf("expected 8.8.8.8:53, got %s", servers[0])
	}
}

func TestEffectiveServers_Fallback(t *testing.T) {
	// No configured servers → falls back to /etc/resolv.conf or public DNS.
	r := New(nil, 5*time.Second)
	servers := r.effectiveServers()
	if len(servers) == 0 {
		t.Error("effectiveServers should always return at least one server")
	}
}

func TestErrNXDomain_Identity(t *testing.T) {
	if !errors.Is(ErrNXDomain, ErrNXDomain) {
		t.Error("ErrNXDomain should satisfy errors.Is(ErrNXDomain, ErrNXDomain)")
	}
}

func TestErrZoneDeleted_Identity(t *testing.T) {
	if !errors.Is(ErrZoneDeleted, ErrZoneDeleted) {
		t.Error("ErrZoneDeleted should satisfy errors.Is")
	}
}

func TestErrNotImplemented_NotNXDomain(t *testing.T) {
	if errors.Is(ErrNotImplemented, ErrNXDomain) {
		t.Error("ErrNotImplemented should not satisfy ErrNXDomain")
	}
}
