package nmc

import "errors"

// ErrActiveNotAuthorized is returned by MustActive when a handler reaches an
// active/exploitation path without the caller having set the explicit consent
// flag (confirm=true / authorized=true). It is the D6 chokepoint's error value.
//
// Per the Appendix D error taxonomy this is a PROTOCOL error, not a Finding: the
// agent must re-issue the call with explicit consent, so an active handler should
// return it as the handler error (nil result, zero output) rather than packaging
// it as a Finding with state=error. The SDK packs a returned error into an
// IsError CallToolResult the agent can read and act on.
var ErrActiveNotAuthorized = errors.New("active/exploitation path requires explicit confirm=true (D6)")

// MustActive enforces D6: it returns ErrActiveNotAuthorized when active is false,
// and nil when active is true. Call it as the first statement of every
// confirm_*/attack_*/read_* (and any other target-touching) handler:
//
//	if err := nmc.MustActive(in.Confirm); err != nil {
//	    return nil, Out{}, err
//	}
//
// This single line is the suite's guarantee that an agent cannot trigger an
// active path it half-understands without an explicit, per-call opt-in (§10/A3).
// Code review rejects any active handler that does not call it.
func MustActive(active bool) error {
	if !active {
		return ErrActiveNotAuthorized
	}
	return nil
}
