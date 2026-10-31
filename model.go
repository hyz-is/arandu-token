package token

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/arandu-io/framework/http/middleware"
)

// The tables this package owns. They carry the package's name so that they
// cannot collide with a devices table or a tokens table the application
// already has.
const (
	credentialsTable = "token_credentials"
	devicesTable     = "token_devices"
)

// The kinds of credential a row holds.
const (
	kindAccess  = "access"
	kindRefresh = "refresh"
)

// The widths the identifier columns are created with, and so the longest a
// value may be.
const (
	maxIdentifierLen = 64
	maxNameLen       = 120
	maxPlatformLen   = 32
	maxIPLen         = 64
)

// Digest is the SHA-256 of a token, and all the store ever holds of one.
// It is the type the framework's TokenResolver is handed.
type Digest = middleware.TokenDigest

// DigestOf returns the digest of a token: the one Resolve is asked about, and
// the one the store keeps when the token is issued.
func DigestOf(token string) Digest { return middleware.DigestToken(token) }

// Principal is who a valid access token was issued to.
//
// WorkspaceID is a candidate. It is the workspace the session was bound to
// when the token was issued, and it says nothing about whether the user still
// belongs to it. The application revalidates the membership on every request
// and only then issues the Grant: the tenant of data comes from the Grant and
// never from here.
type Principal struct {
	// UserID is the account the token was issued to.
	UserID string
	// WorkspaceID is the workspace the session is bound to, empty when it is
	// bound to none yet.
	WorkspaceID string
	// DeviceID is the device the token was issued to.
	DeviceID string
	// FamilyID names the session the token belongs to.
	FamilyID string
}

// Device is a place a user is signed in: an install of a native app.
//
// Issue takes the first three fields from the application, which takes them
// from the app that is signing in. ListDevices fills the rest.
type Device struct {
	// ID identifies the install. The native app generates it once and sends it
	// on every sign-in, so that signing in again on the same device replaces its
	// session instead of adding a second one. It is scoped to the user: the same
	// value on two accounts is two devices.
	ID string
	// Name is what the person calls the device, "Pixel de Ana". It is shown in
	// the list of devices and nowhere else.
	Name string
	// Platform is what runs the app: "android", "ios", "macos", "windows",
	// "linux". It is free text of at most 32 characters.
	Platform string

	// LastUsedAt is the last time a token of this device was accepted, at the
	// resolution of Config.TouchInterval. ListDevices fills it.
	LastUsedAt time.Time
	// LastIP is the address of that request. ListDevices fills it.
	LastIP string
	// CreatedAt is when the device first signed in. ListDevices fills it.
	CreatedAt time.Time
}

// Cleaned is what a clean removed.
type Cleaned struct {
	// Credentials is the expired and revoked tokens deleted.
	Credentials int64
	// Devices is the devices with no token left that had not been seen since the
	// retention ran out.
	Devices int64
}

// identifier is what an account, workspace or device identifier may be:
// letters, digits and the punctuation of uuids, ulids, slugs and e-mail style
// subjects, and nothing that needs quoting.
var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@-]*$`)

// checkID reports what an identifier cannot be.
func checkID(field, value string, required bool) error {
	if value == "" {
		if required {
			return fmt.Errorf("token: %s is required", field)
		}
		return nil
	}
	if len(value) > maxIdentifierLen || !identifier.MatchString(value) {
		return fmt.Errorf("token: %s has to be up to %d letters, digits or . _ : @ - characters", field, maxIdentifierLen)
	}
	return nil
}

// checkDevice reports what a device cannot be, and returns it with its free
// text cleaned: a name or a platform the app sends too long is cut and stripped
// of control characters, not refused, because a sign-in that fails over a
// device name is a worse outcome than a short name.
func checkDevice(d Device) (Device, error) {
	if err := checkID("device ID", d.ID, true); err != nil {
		return Device{}, err
	}
	d.Name = clean(d.Name, maxNameLen)
	d.Platform = clean(d.Platform, maxPlatformLen)
	return d, nil
}

// clean tidies a free-text value: line breaks and tabs become spaces, other
// control characters are dropped, runs of spaces collapse, and the result is cut
// to max characters.
func clean(value string, max int) string {
	value = strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			return ' '
		case unicode.IsControl(r):
			return -1
		}
		return r
	}, value)), " ")
	if r := []rune(value); len(r) > max {
		value = string(r[:max])
	}
	return value
}
