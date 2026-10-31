package token

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/arandu-io/hesape/auth"
)

// SignInThrottle is the framework's throttle of sign-in attempts: Attempt takes
// a unit before the credential is checked, Refund gives it back when the check
// never reached the credential, and Clear forgets the failures after a good
// sign-in. Limiter implements it, and so does the framework's MemoryThrottle.
type SignInThrottle = auth.SignInThrottle

// Guard runs one check of credentials behind a throttle, so that the sign-in of
// a native app, which has no Turnstile to put in front of it, cannot be
// guessed at.
//
// The password and the second factor are the application's: check is the
// function that verifies them and answers whether they were right. Guard takes
// the unit before calling it, so a burst of simultaneous guesses does not all
// get through, and then:
//
//   - a throttle that refuses answers a *LockedError, and check is not called;
//   - check answering an error gives the unit back and returns the error, since
//     an attempt that never reached the credential costs nothing;
//   - check answering false returns ErrBadCredentials, and the failure stays
//     counted;
//   - check answering true forgets the account's failures.
//
// scope is the throttle's tenant, a fixed string for a sign-in that happens
// before any workspace is chosen. identity is the account being tried, the
// e-mail or the CPF as the person typed it, normalised the same way every time.
// client is the address of the request.
func Guard(ctx context.Context, throttle SignInThrottle, scope, identity, client string, check func(context.Context) (bool, error)) error {
	if retry, ok := throttle.Attempt(ctx, scope, identity, client); !ok {
		return &LockedError{RetryAfter: retry}
	}
	good, err := check(ctx)
	if err != nil {
		throttle.Refund(ctx, scope, identity, client)
		return err
	}
	if !good {
		return ErrBadCredentials
	}
	throttle.Clear(ctx, scope, identity, client)
	return nil
}

// Defaults of a LimiterPolicy.
const (
	// DefaultMaxFailuresPerAccount is how many attempts one account takes from
	// all addresses together before it locks.
	DefaultMaxFailuresPerAccount = 5
	// DefaultMaxFailuresPerClient is how many attempts one address takes across
	// all accounts before it locks.
	DefaultMaxFailuresPerClient = 25
	// DefaultLimiterWindow is how long attempts accumulate before the count
	// starts over.
	DefaultLimiterWindow = 15 * time.Minute
	// DefaultBaseLockout is the first lockout of a key.
	DefaultBaseLockout = 30 * time.Second
	// DefaultMaxLockout is the longest a lockout grows to.
	DefaultMaxLockout = time.Hour
	// DefaultLockoutFactor is what each lockout is multiplied by for the next.
	DefaultLockoutFactor = 2
	// DefaultStrikeMemory is how long after a lockout the key remembers it, so
	// that the next one is longer.
	DefaultStrikeMemory = 24 * time.Hour
	// DefaultMaxTracked is how many keys a Limiter holds at most.
	DefaultMaxTracked = 1 << 16
)

// LimiterPolicy is how a Limiter counts and how it punishes. A zero field is
// its default; a negative one is refused.
type LimiterPolicy struct {
	// MaxFailuresPerAccount is the attempts an account takes, whatever address
	// they come from, before it locks. This is the budget the framework's
	// MemoryThrottle does not have: it counts an account per address, so a guess
	// spread over many addresses is not slowed by it.
	MaxFailuresPerAccount int
	// MaxFailuresPerClient is the attempts an address takes, whatever accounts
	// it names, before it locks.
	MaxFailuresPerClient int
	// Window is how long attempts accumulate without a lockout before the count
	// starts over.
	Window time.Duration
	// BaseLockout is how long a key is locked the first time it spends its
	// budget.
	BaseLockout time.Duration
	// Factor is what the lockout is multiplied by each time the same key locks
	// again inside StrikeMemory.
	Factor int
	// MaxLockout caps the lockout.
	MaxLockout time.Duration
	// StrikeMemory is how long a key remembers it locked. A key quiet for this
	// long starts again at BaseLockout.
	StrikeMemory time.Duration
	// MaxTracked caps how many keys are held. An attacker naming a million
	// addresses fills the table with entries meant to stop them, and the cap is
	// what keeps that bounded.
	MaxTracked int
	// Clock is the time source. Nil means time.Now. It exists so that a lockout
	// can be proved without waiting for it.
	Clock func() time.Time
}

func (p LimiterPolicy) withDefaults() (LimiterPolicy, error) {
	if p.MaxFailuresPerAccount < 0 || p.MaxFailuresPerClient < 0 || p.Window < 0 || p.BaseLockout < 0 ||
		p.Factor < 0 || p.MaxLockout < 0 || p.StrikeMemory < 0 || p.MaxTracked < 0 {
		return LimiterPolicy{}, errors.New("token: a LimiterPolicy field is negative: zero means the default, and nothing else is a valid size or duration")
	}
	if p.MaxFailuresPerAccount == 0 {
		p.MaxFailuresPerAccount = DefaultMaxFailuresPerAccount
	}
	if p.MaxFailuresPerClient == 0 {
		p.MaxFailuresPerClient = DefaultMaxFailuresPerClient
	}
	if p.Window == 0 {
		p.Window = DefaultLimiterWindow
	}
	if p.BaseLockout == 0 {
		p.BaseLockout = DefaultBaseLockout
	}
	if p.Factor == 0 {
		p.Factor = DefaultLockoutFactor
	}
	if p.MaxLockout == 0 {
		p.MaxLockout = DefaultMaxLockout
	}
	if p.StrikeMemory == 0 {
		p.StrikeMemory = DefaultStrikeMemory
	}
	if p.MaxTracked == 0 {
		p.MaxTracked = DefaultMaxTracked
	}
	if p.Clock == nil {
		p.Clock = time.Now
	}
	if p.Factor < 1 || p.MaxLockout < p.BaseLockout {
		return LimiterPolicy{}, fmt.Errorf("token: a LimiterPolicy needs a Factor of at least 1 and a MaxLockout (%s) of at least its BaseLockout (%s)", p.MaxLockout, p.BaseLockout)
	}
	return p, nil
}

// Limiter is a SignInThrottle with a progressive lockout, held in the memory of
// the process.
//
// It counts attempts against two budgets at once, the account and the address,
// in one indivisible step, so a burst of simultaneous guesses sees the budget it
// really has. The attempt that spends a budget locks the key: for BaseLockout
// the first time, and each time the key locks again within StrikeMemory, Factor
// times longer, up to MaxLockout. A refused attempt costs nothing, so hammering
// a locked account does not extend the lockout.
//
// A good sign-in forgets the account entirely and gives the address back one
// unit, and nothing more: a script that owns one account does not buy itself a
// fresh budget against the others.
//
// It is right for one instance. Behind several, each holds its own counters and
// the budgets multiply by the number of instances; an application that runs
// more than one passes Guard a throttle backed by a shared store, since Guard
// takes the interface.
//
// It starts no goroutine: what it removes it removes on the call that would
// have grown it.
type Limiter struct {
	mu     sync.Mutex
	policy LimiterPolicy
	keys   map[string]*attempts
	sweep  time.Time
}

// attempts is what the limiter remembers about one key.
type attempts struct {
	count       int
	windowEnds  time.Time
	lockedUntil time.Time
	strikes     int
	lastStrike  time.Time
}

var _ SignInThrottle = (*Limiter)(nil)

// NewLimiter returns a Limiter that counts under policy, or the reason the
// policy cannot be used.
func NewLimiter(policy LimiterPolicy) (*Limiter, error) {
	policy, err := policy.withDefaults()
	if err != nil {
		return nil, err
	}
	return &Limiter{policy: policy, keys: map[string]*attempts{}, sweep: policy.Clock()}, nil
}

// Attempt takes one unit from the account's budget and one from the address's,
// or refuses without taking anything.
func (l *Limiter) Attempt(_ context.Context, scope, identity, client string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.policy.Clock()
	l.trim(now)

	account, address := accountKey(scope, identity), clientKey(scope, client)
	for _, key := range []string{account, address} {
		if a, ok := l.keys[key]; ok {
			l.settle(a, now)
			if now.Before(a.lockedUntil) {
				return a.lockedUntil.Sub(now), false
			}
		}
	}
	l.spend(account, l.policy.MaxFailuresPerAccount, now)
	l.spend(address, l.policy.MaxFailuresPerClient, now)
	return 0, true
}

// Refund gives back the unit Attempt took from each budget, for an attempt that
// never reached the credential. It never clears a count, and a lockout that the
// refunded attempt had caused ends with it.
func (l *Limiter) Refund(_ context.Context, scope, identity, client string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.giveBack(accountKey(scope, identity), l.policy.MaxFailuresPerAccount)
	l.giveBack(clientKey(scope, client), l.policy.MaxFailuresPerClient)
}

// Clear forgets the account, lockouts included, and gives the address back the
// unit this attempt took. Call it on a good sign-in.
func (l *Limiter) Clear(_ context.Context, scope, identity, client string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.keys, accountKey(scope, identity))
	l.giveBack(clientKey(scope, client), l.policy.MaxFailuresPerClient)
}

// Len reports how many keys are held, so that a test can prove the table is
// bounded.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.keys)
}

// settle moves a key past what has ended: a lockout that is over, and a window
// that ran out without one. The caller holds the lock.
func (l *Limiter) settle(a *attempts, now time.Time) {
	if !a.lockedUntil.IsZero() && !now.Before(a.lockedUntil) {
		a.lockedUntil = time.Time{}
		a.count = 0
	}
	if a.lockedUntil.IsZero() && a.count > 0 && !now.Before(a.windowEnds) {
		a.count = 0
	}
}

// spend adds one to a key and locks it when that spends the budget. The caller
// holds the lock.
func (l *Limiter) spend(key string, budget int, now time.Time) {
	a, ok := l.keys[key]
	if !ok {
		a = &attempts{}
		l.keys[key] = a
	}
	if a.count == 0 {
		a.windowEnds = now.Add(l.policy.Window)
	}
	a.count++
	if a.count < budget {
		return
	}
	// The strikes of a key that has been quiet for StrikeMemory are forgotten, so
	// that somebody who mistyped once last month is not on the third lockout.
	if !a.lastStrike.IsZero() && now.Sub(a.lastStrike) >= l.policy.StrikeMemory {
		a.strikes = 0
	}
	a.strikes++
	a.lastStrike = now
	a.lockedUntil = now.Add(l.lockout(a.strikes))
}

// lockout is BaseLockout multiplied by Factor once for every strike after the
// first, capped at MaxLockout. It stops multiplying as soon as it reaches the
// cap, so a long history cannot overflow it.
func (l *Limiter) lockout(strikes int) time.Duration {
	d := l.policy.BaseLockout
	for i := 1; i < strikes && d < l.policy.MaxLockout; i++ {
		d *= time.Duration(l.policy.Factor)
	}
	if d > l.policy.MaxLockout {
		d = l.policy.MaxLockout
	}
	return d
}

// giveBack takes one unit off a key. A key that was locked by the unit that
// goes back is unlocked, and one with nothing left to remember is dropped. The
// caller holds the lock.
func (l *Limiter) giveBack(key string, budget int) {
	a, ok := l.keys[key]
	if !ok {
		return
	}
	if a.count > 0 {
		a.count--
	}
	// A key locks when its count reaches the budget, so a count below the budget
	// means the unit that goes back was one of those that locked it.
	if !a.lockedUntil.IsZero() && a.count < budget {
		a.lockedUntil = time.Time{}
		if a.strikes > 0 {
			a.strikes--
		}
	}
	if a.count == 0 && a.lockedUntil.IsZero() && a.strikes == 0 {
		delete(l.keys, key)
	}
}

// trim keeps the table bounded. The caller holds the lock.
//
// Once per window it drops every key with nothing left to remember. At the cap
// it also evicts keys that are not locked, two per call, so the table stops
// growing while a lockout in force is never forgotten to make room.
func (l *Limiter) trim(now time.Time) {
	if now.Sub(l.sweep) >= l.policy.Window {
		l.sweep = now
		for key, a := range l.keys {
			if l.forgettable(a, now) {
				delete(l.keys, key)
			}
		}
	}
	for evicted := 0; len(l.keys) >= l.policy.MaxTracked && evicted < 2; {
		removed := false
		for key, a := range l.keys {
			if a.lockedUntil.IsZero() || !now.Before(a.lockedUntil) {
				delete(l.keys, key)
				evicted++
				removed = true
				break
			}
		}
		if !removed {
			return
		}
	}
}

// forgettable reports whether a key holds nothing worth keeping at now.
func (l *Limiter) forgettable(a *attempts, now time.Time) bool {
	if now.Before(a.lockedUntil) {
		return false
	}
	if a.count > 0 && now.Before(a.windowEnds) {
		return false
	}
	return a.strikes == 0 || now.Sub(a.lastStrike) >= l.policy.StrikeMemory
}

// accountKey and clientKey name the two budgets. The scope is part of both, and
// the pieces are separated by a byte that none of them can contain once control
// characters are removed, so that two different triples never make one key.
func accountKey(scope, identity string) string {
	return "a\x00" + sanitize(scope) + "\x00" + sanitize(identity)
}
func clientKey(scope, client string) string {
	return "c\x00" + sanitize(scope) + "\x00" + sanitize(client)
}

// sanitize lower-cases and strips control characters from a key part, so that
// "Ana@Example.com" and "ana@example.com" are one account and a NUL cannot be
// used to forge a separator.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.ToLower(strings.TrimSpace(s)))
}
