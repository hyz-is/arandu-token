package token

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
)

// redacted is what a secret prints as, in every verb and every encoding.
const redacted = "[redacted]"

// BearerScheme is the Authorization scheme a token travels under, and the
// token_type of the answer Reveal builds.
const BearerScheme = "Bearer"

// Secret is a token that cannot be printed, logged or encoded by accident.
//
// It is a struct and not a string so that string(secret) does not compile, and
// every way of formatting one answers "[redacted]": String, GoString and every
// fmt verb through Format, MarshalText, MarshalJSON and LogValue for log/slog.
// The only way to the value is Reveal, and a call to it is the line a reviewer
// looks for.
//
// The zero Secret is empty and prints the same way, so a log line cannot tell a
// missing token from a present one.
//
// The value sits behind a pointer for a reason of its own. When fmt is given a
// verb that does not fit the operand, it prints the operand's fields itself and
// calls no Format, String or LogValue on the way, so a string field would be
// printed in the open. A pointer field is printed as an address.
type Secret struct{ value *string }

// newSecret wraps a token.
func newSecret(value string) Secret { return Secret{value: &value} }

// Reveal returns the token. Call it where the token is handed to its owner, in
// the body of the answer to a sign-in, and nowhere else.
func (s Secret) Reveal() string {
	if s.value == nil {
		return ""
	}
	return *s.value
}

// IsZero reports whether the secret holds nothing.
func (s Secret) IsZero() bool { return s.Reveal() == "" }

// String answers "[redacted]".
func (Secret) String() string { return redacted }

// GoString answers "[redacted]" for %#v.
func (Secret) GoString() string { return redacted }

// Format answers "[redacted]" for every verb, so that %d, %x or %q does not
// find a way to the value that String closes.
func (Secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// MarshalText answers "[redacted]", which is what encoding/json uses for a map
// key and what text encoders use for a value.
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// MarshalJSON answers the JSON string "[redacted]". An application that
// serialises a Pair directly sends a body that does not work, and notices in
// development rather than leaking in production; Reveal is how the real body is
// built.
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// LogValue answers "[redacted]" to log/slog.
func (Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

var (
	_ fmt.Stringer   = Secret{}
	_ fmt.GoStringer = Secret{}
	_ fmt.Formatter  = Secret{}
	_ slog.LogValuer = Secret{}
)

// Pair is the two tokens a device holds, and when each stops working.
//
// The tokens are Secrets: formatting, logging or marshalling a Pair shows their
// expiry and not the tokens. Reveal builds the body that hands them over.
type Pair struct {
	// Access is the short-lived token the device sends on every request.
	Access Secret
	// Refresh is the long-lived token the device exchanges for the next pair.
	Refresh Secret
	// AccessExpires is when Access stops being accepted.
	AccessExpires time.Time
	// RefreshExpires is when Refresh stops being accepted.
	RefreshExpires time.Time
	// WorkspaceID is the workspace the pair is bound to: a candidate, which the
	// application revalidates on every request.
	WorkspaceID string
	// DeviceID is the device the pair belongs to.
	DeviceID string

	// accessTTL is the lifetime Access was issued with, for Reveal's expires_in.
	accessTTL time.Duration
}

// LogValue answers the expiry and the binding, and no token.
func (p Pair) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Time("access_expires", p.AccessExpires),
		slog.Time("refresh_expires", p.RefreshExpires),
		slog.String("workspace_id", p.WorkspaceID),
		slog.String("device_id", p.DeviceID),
	)
}

var _ slog.LogValuer = Pair{}

// Reveal returns the pair as the body of the answer that hands it to its
// owner: marshalling the result writes the tokens, which is its whole purpose,
// while formatting and logging it print "[redacted]".
func (p Pair) Reveal() Revealed {
	return Revealed{body: &revealedBody{
		TokenType:        BearerScheme,
		AccessToken:      p.Access.Reveal(),
		RefreshToken:     p.Refresh.Reveal(),
		ExpiresIn:        int64(p.accessTTL / time.Second),
		AccessExpiresAt:  p.AccessExpires.UTC(),
		RefreshExpiresAt: p.RefreshExpires.UTC(),
		WorkspaceID:      p.WorkspaceID,
		DeviceID:         p.DeviceID,
	}}
}

// Revealed is a Pair with its tokens in the open, shaped as the JSON body of a
// sign-in or a refresh:
//
//	{"token_type":"Bearer","access_token":"...","refresh_token":"...",
//	 "expires_in":900,"access_expires_at":"...","refresh_expires_at":"...",
//	 "workspace_id":"...","device_id":"..."}
//
// Marshalling it writes the tokens. Everything else that could print it, fmt in
// any verb and log/slog, prints "[redacted]" instead, so the one place the
// tokens leave this package is the encoder the application calls on purpose.
// The body sits behind a pointer for the reason Secret's value does.
type Revealed struct{ body *revealedBody }

// revealedBody is the JSON of a Revealed.
type revealedBody struct {
	TokenType        string    `json:"token_type"`
	AccessToken      string    `json:"access_token"`
	RefreshToken     string    `json:"refresh_token"`
	ExpiresIn        int64     `json:"expires_in"`
	AccessExpiresAt  time.Time `json:"access_expires_at"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
	WorkspaceID      string    `json:"workspace_id"`
	DeviceID         string    `json:"device_id"`
}

// MarshalJSON writes the body, tokens included.
func (r Revealed) MarshalJSON() ([]byte, error) {
	if r.body == nil {
		return []byte("null"), nil
	}
	return json.Marshal(r.body)
}

// String answers "[redacted]".
func (Revealed) String() string { return redacted }

// GoString answers "[redacted]" for %#v.
func (Revealed) GoString() string { return redacted }

// Format answers "[redacted]" for every verb.
func (Revealed) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// LogValue answers "[redacted]" to log/slog.
func (Revealed) LogValue() slog.Value { return slog.StringValue(redacted) }

var (
	_ fmt.Stringer   = Revealed{}
	_ fmt.GoStringer = Revealed{}
	_ fmt.Formatter  = Revealed{}
	_ slog.LogValuer = Revealed{}
	_ json.Marshaler = Revealed{}
)
