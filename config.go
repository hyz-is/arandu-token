package token

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// The defaults for the optional settings. They are constants rather than
// literals inside Config.withDefaults, so the value a reader finds here is the
// value the package uses.
const (
	// DefaultAccessPrefix is what an access token starts with when Config leaves
	// AccessPrefix empty.
	DefaultAccessPrefix = "tka_"
	// DefaultRefreshPrefix is what a refresh token starts with when Config
	// leaves RefreshPrefix empty.
	DefaultRefreshPrefix = "tkr_"
	// DefaultAccessTTL is how long an access token lives when Config leaves
	// AccessTTL at zero.
	DefaultAccessTTL = 15 * time.Minute
	// DefaultRefreshTTL is how long a refresh token lives when Config leaves
	// RefreshTTL at zero.
	DefaultRefreshTTL = 60 * 24 * time.Hour
	// DefaultRetention is how long an expired or revoked credential stays in the
	// table when Config leaves Retention at zero.
	DefaultRetention = 7 * 24 * time.Hour
	// DefaultTouchInterval is the least time between two writes of the same
	// credential's last use when Config leaves TouchInterval at zero.
	DefaultTouchInterval = time.Minute
	// DefaultCleanSpec is when the clean runs when Config leaves CleanSpec empty:
	// every day at 03:17.
	DefaultCleanSpec = "17 3 * * *"

	// MaxAccessTTL is the longest an access token may live. An access token that
	// outlives a day is a session, and a session is what the refresh token is
	// for.
	MaxAccessTTL = 24 * time.Hour
	// MaxRefreshTTL is the longest a refresh token may live.
	MaxRefreshTTL = 400 * 24 * time.Hour
	// MaxReuseGrace is the longest ReuseGrace may be.
	MaxReuseGrace = 2 * time.Minute

	// CleanDisabled is the CleanSpec that declares no scheduled clean. The
	// application then calls Service.Clean itself, and a table nobody cleans
	// only grows.
	CleanDisabled = "-"
)

// prefixPattern is what a token prefix may be: a letter, then letters, digits,
// underscores and hyphens, up to sixteen characters. A prefix is read by people
// and by secret scanners, and neither needs more; what is excluded is anything
// that would need escaping in a header, a URL or a shell.
var prefixPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,15}$`)

// Config is what the application passes when it wires this package.
//
// A typed struct rather than a map: a misspelled key in a map is a setting that
// silently keeps its default, and here a field that does not exist does not
// compile. The zero value is a valid configuration.
//
// It names no tenant and no workspace. A workspace is a candidate stored beside
// a credential, never a tenant: the application revalidates it on every
// request and the Grant carries the tenant.
type Config struct {
	// AccessPrefix is the readable start of an access token. Empty means
	// DefaultAccessPrefix. An application names its own (alpra_), so that a
	// credential found in a log, a repository or a crash report says whose it is
	// and a secret scanner can match it.
	AccessPrefix string

	// RefreshPrefix is the readable start of a refresh token. Empty means
	// DefaultRefreshPrefix. It differs from AccessPrefix, and neither is the
	// start of the other, so the two kinds cannot be told apart wrongly.
	RefreshPrefix string

	// AccessTTL is how long an access token lives. Zero means DefaultAccessTTL;
	// anything above MaxAccessTTL is refused.
	AccessTTL time.Duration

	// RefreshTTL is how long a refresh token lives, counted from the one that
	// rotated into it: a device that is used keeps its session, one that sits
	// still for RefreshTTL loses it. Zero means DefaultRefreshTTL; it is at
	// least AccessTTL and at most MaxRefreshTTL.
	RefreshTTL time.Duration

	// Retention is how long an expired or revoked credential is kept before the
	// clean deletes it. Zero means DefaultRetention.
	//
	// It is also how long a refresh token that was rotated stays recognisable as
	// rotated: presenting it inside Retention is a reuse and revokes the family,
	// and after the clean it is a token nobody has heard of.
	Retention time.Duration

	// ReuseGrace is the time after a rotation in which presenting the old refresh
	// token is refused as invalid and does not revoke the family. Zero, the
	// default, treats every reuse as theft. A client that refreshes from two
	// requests at once sends the same token twice, and the second would otherwise
	// sign the device out; a few seconds here absorb that at the price of those
	// seconds of exposure. It is at most MaxReuseGrace.
	ReuseGrace time.Duration

	// TouchInterval is the least time between two writes of a credential's last
	// use and its device's last address. Zero means DefaultTouchInterval; a
	// negative value writes on every request.
	TouchInterval time.Duration

	// CleanSpec is the five-field cron expression of the scheduled clean. Empty
	// means DefaultCleanSpec and CleanDisabled declares none.
	CleanSpec string

	// Events receives what happened to a credential: issued, refreshed, reuse
	// detected, revoked, switched. Nil records nothing. See Recorder.
	Events Recorder

	// Clock is the time source. Nil means time.Now. It exists so that expiry,
	// rotation and the clean can be proved without sleeping.
	Clock func() time.Time
}

// Validate reports what the configuration cannot be used with.
//
// It is called by New, so an application with a setting that cannot work fails
// where it is wired rather than on the first request that needed it.
func (c Config) Validate() error {
	access, refresh := c.AccessPrefix, c.RefreshPrefix
	if access == "" {
		access = DefaultAccessPrefix
	}
	if refresh == "" {
		refresh = DefaultRefreshPrefix
	}
	for _, p := range []struct{ name, prefix string }{{"AccessPrefix", access}, {"RefreshPrefix", refresh}} {
		if !prefixPattern.MatchString(p.prefix) {
			return fmt.Errorf("token: Config.%s is %q and has to be a letter followed by up to fifteen letters, digits, underscores or hyphens", p.name, p.prefix)
		}
	}
	if strings.HasPrefix(access, refresh) || strings.HasPrefix(refresh, access) {
		return fmt.Errorf("token: Config.AccessPrefix %q and Config.RefreshPrefix %q have to differ, and neither can start the other", access, refresh)
	}

	accessTTL, refreshTTL := c.AccessTTL, c.RefreshTTL
	if accessTTL < 0 || accessTTL > MaxAccessTTL {
		return fmt.Errorf("token: Config.AccessTTL is %s and has to be between 0 and %s, where 0 means %s", accessTTL, MaxAccessTTL, DefaultAccessTTL)
	}
	if refreshTTL < 0 || refreshTTL > MaxRefreshTTL {
		return fmt.Errorf("token: Config.RefreshTTL is %s and has to be between 0 and %s, where 0 means %s", refreshTTL, MaxRefreshTTL, DefaultRefreshTTL)
	}
	if accessTTL == 0 {
		accessTTL = DefaultAccessTTL
	}
	if refreshTTL == 0 {
		refreshTTL = DefaultRefreshTTL
	}
	if refreshTTL < accessTTL {
		return fmt.Errorf("token: Config.RefreshTTL (%s) is shorter than Config.AccessTTL (%s): the refresh token is what outlives the access token", refreshTTL, accessTTL)
	}

	if c.Retention < 0 {
		return fmt.Errorf("token: Config.Retention is %s and cannot be negative", c.Retention)
	}
	if c.ReuseGrace < 0 || c.ReuseGrace > MaxReuseGrace {
		return fmt.Errorf("token: Config.ReuseGrace is %s and has to be between 0 and %s", c.ReuseGrace, MaxReuseGrace)
	}
	if c.CleanSpec != "" && c.CleanSpec != CleanDisabled && len(strings.Fields(c.CleanSpec)) != 5 {
		return fmt.Errorf("token: Config.CleanSpec is %q and has to be five cron fields, or %q for none", c.CleanSpec, CleanDisabled)
	}
	return nil
}

// withDefaults returns the configuration with the optional fields filled in.
//
// It runs after Validate and never before: filling a default in first would
// hide the value somebody actually wrote from the check that would have refused
// it.
func (c Config) withDefaults() Config {
	if c.AccessPrefix == "" {
		c.AccessPrefix = DefaultAccessPrefix
	}
	if c.RefreshPrefix == "" {
		c.RefreshPrefix = DefaultRefreshPrefix
	}
	if c.AccessTTL == 0 {
		c.AccessTTL = DefaultAccessTTL
	}
	if c.RefreshTTL == 0 {
		c.RefreshTTL = DefaultRefreshTTL
	}
	if c.Retention == 0 {
		c.Retention = DefaultRetention
	}
	if c.TouchInterval == 0 {
		c.TouchInterval = DefaultTouchInterval
	}
	if c.CleanSpec == "" {
		c.CleanSpec = DefaultCleanSpec
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	return c
}

// errNilDatabase is what the constructors answer to a missing handle.
var errNilDatabase = errors.New("token: a database handle is required: this package owns tables, and there is no in-memory mode that would let it start without one")
