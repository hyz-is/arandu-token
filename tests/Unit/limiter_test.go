package unit_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arandu-io/hesape/auth"

	token "github.com/hyz-is/arandu-token"
)

var ctx = context.Background()

type fakeTime struct {
	mu sync.Mutex
	t  time.Time
}

func (f *fakeTime) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeTime) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = f.t.Add(d)
}

func newLimiter(t *testing.T, policy token.LimiterPolicy) (*token.Limiter, *fakeTime) {
	t.Helper()
	now := &fakeTime{t: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)}
	policy.Clock = now.Now
	l, err := token.NewLimiter(policy)
	if err != nil {
		t.Fatal(err)
	}
	return l, now
}

// fail takes a unit the way a wrong password does: Attempt, and no Clear.
func fail(l *token.Limiter, account, client string) (time.Duration, bool) {
	return l.Attempt(ctx, "app", account, client)
}

func TestTheLimiterIsASignInThrottle(t *testing.T) {
	var _ auth.SignInThrottle = (*token.Limiter)(nil)
	var _ token.SignInThrottle = (*token.Limiter)(nil)
}

func TestAnAccountLocksAfterItsBudgetWhateverTheAddress(t *testing.T) {
	l, _ := newLimiter(t, token.LimiterPolicy{MaxFailuresPerAccount: 3})

	// Three attempts from three different addresses: the guess that spreads
	// itself over addresses is what the framework's per-address budget misses.
	for i := 0; i < 3; i++ {
		if _, ok := fail(l, "ana@example.com", fmt.Sprintf("198.51.100.%d", i)); !ok {
			t.Fatalf("attempt %d was refused before the budget was spent", i+1)
		}
	}
	retry, ok := fail(l, "ana@example.com", "203.0.113.50")
	if ok || retry != 30*time.Second {
		t.Fatalf("the fourth attempt = %v, %v; want a refusal of 30s", retry, ok)
	}
	// Other accounts are not affected, and the account is the same however it
	// was typed.
	if _, ok := fail(l, "bruno@example.com", "203.0.113.50"); !ok {
		t.Fatal("another account was locked")
	}
	if _, ok := fail(l, "  ANA@example.com ", "203.0.113.51"); ok {
		t.Fatal("a different spelling of the account got past the lock")
	}
}

func TestAnAddressLocksAfterItsBudgetWhateverTheAccount(t *testing.T) {
	l, _ := newLimiter(t, token.LimiterPolicy{MaxFailuresPerClient: 4, MaxFailuresPerAccount: 100})
	for i := 0; i < 4; i++ {
		if _, ok := fail(l, fmt.Sprintf("user%d@example.com", i), "198.51.100.1"); !ok {
			t.Fatalf("attempt %d refused", i+1)
		}
	}
	if _, ok := fail(l, "fresh@example.com", "198.51.100.1"); ok {
		t.Fatal("the address took a fifth attempt")
	}
	if _, ok := fail(l, "fresh@example.com", "198.51.100.2"); !ok {
		t.Fatal("another address was locked")
	}
}

func TestTheLockoutGrowsEachTimeAndForgetsAfterAQuietSpell(t *testing.T) {
	l, now := newLimiter(t, token.LimiterPolicy{
		MaxFailuresPerAccount: 2, BaseLockout: 10 * time.Second, Factor: 3, MaxLockout: time.Minute, StrikeMemory: time.Hour,
	})
	lock := func() time.Duration {
		t.Helper()
		for {
			retry, ok := fail(l, "ana", "ip")
			if !ok {
				return retry
			}
		}
	}

	if got := lock(); got != 10*time.Second {
		t.Fatalf("first lockout = %s, want 10s", got)
	}
	now.Advance(10 * time.Second)
	if got := lock(); got != 30*time.Second {
		t.Fatalf("second lockout = %s, want 30s", got)
	}
	now.Advance(30 * time.Second)
	if got := lock(); got != time.Minute {
		t.Fatalf("third lockout = %s, want the cap of 1m, not 90s", got)
	}
	now.Advance(time.Minute)
	if got := lock(); got != time.Minute {
		t.Fatalf("fourth lockout = %s, want to stay at the cap", got)
	}

	// Quiet for the strike memory, and it starts again.
	now.Advance(time.Minute + time.Hour)
	if got := lock(); got != 10*time.Second {
		t.Fatalf("lockout after a quiet spell = %s, want 10s", got)
	}
}

func TestARefusedAttemptCostsNothingAndDoesNotExtendTheLockout(t *testing.T) {
	l, now := newLimiter(t, token.LimiterPolicy{MaxFailuresPerAccount: 1, BaseLockout: time.Minute})
	if _, ok := fail(l, "ana", "ip"); !ok {
		t.Fatal("the first attempt was refused")
	}
	for i := 0; i < 20; i++ {
		now.Advance(time.Second)
		fail(l, "ana", "ip")
	}
	// 20 seconds of hammering later, the lock still ends a minute after it began.
	retry, ok := fail(l, "ana", "ip")
	if ok || retry != 40*time.Second {
		t.Fatalf("after the hammering = %v, %v; want 40s left", retry, ok)
	}
}

func TestACountStartsOverAfterTheWindow(t *testing.T) {
	l, now := newLimiter(t, token.LimiterPolicy{MaxFailuresPerAccount: 3, Window: time.Minute})
	fail(l, "ana", "ip")
	fail(l, "ana", "ip")
	now.Advance(2 * time.Minute)
	for i := 0; i < 2; i++ {
		if _, ok := fail(l, "ana", "ip"); !ok {
			t.Fatalf("attempt %d of the new window was refused: the old ones were not forgotten", i+1)
		}
	}
	if _, ok := fail(l, "ana", "ip"); !ok {
		t.Fatal("the third attempt of a window is the one that spends the budget, and it is allowed")
	}
	if _, ok := fail(l, "ana", "ip"); ok {
		t.Fatal("the fourth attempt was allowed")
	}
}

func TestAGoodSignInForgetsTheAccountAndNotTheAddress(t *testing.T) {
	l, _ := newLimiter(t, token.LimiterPolicy{MaxFailuresPerAccount: 3, MaxFailuresPerClient: 5})
	fail(l, "ana", "ip")
	fail(l, "ana", "ip")
	l.Attempt(ctx, "app", "ana", "ip") // the third, which was right
	l.Clear(ctx, "app", "ana", "ip")

	for i := 0; i < 2; i++ {
		if _, ok := fail(l, "ana", "ip"); !ok {
			t.Fatal("the account was not forgotten after a good sign-in")
		}
	}
	// The address keeps what it spent, less the unit the good attempt gave back:
	// 2 + 1 - 1 + 2 = 4 of 5 so far.
	if _, ok := fail(l, "other", "ip"); !ok {
		t.Fatal("the fifth unit of the address was refused")
	}
	if _, ok := fail(l, "another", "ip"); ok {
		t.Fatal("a good sign-in reset the budget of the address")
	}
}

func TestARefundGivesBackTheUnitAndTheLockoutItCaused(t *testing.T) {
	l, _ := newLimiter(t, token.LimiterPolicy{MaxFailuresPerAccount: 2, MaxFailuresPerClient: 10})
	fail(l, "ana", "ip")
	if _, ok := fail(l, "ana", "ip"); !ok { // spends the budget and locks
		t.Fatal("the second attempt was refused")
	}
	if _, ok := fail(l, "ana", "ip"); ok {
		t.Fatal("the account did not lock")
	}
	// The second attempt never reached the credential, and says so.
	l.Refund(ctx, "app", "ana", "ip")
	if _, ok := fail(l, "ana", "ip"); !ok {
		t.Fatal("the lockout caused by a refunded attempt was kept")
	}
	// A refund never clears a count that was really spent.
	l.Refund(ctx, "app", "never", "seen")
}

func TestABurstOfSimultaneousGuessesGetsExactlyTheBudget(t *testing.T) {
	l, _ := newLimiter(t, token.LimiterPolicy{MaxFailuresPerAccount: 5, MaxFailuresPerClient: 1000})
	var (
		allowed atomic.Int64
		wg      sync.WaitGroup
		start   = make(chan struct{})
	)
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			if _, ok := l.Attempt(ctx, "app", "ana", fmt.Sprintf("ip-%d", i)); ok {
				allowed.Add(1)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if allowed.Load() != 5 {
		t.Fatalf("%d of 200 simultaneous attempts got through, want 5", allowed.Load())
	}
}

func TestTheTableIsBounded(t *testing.T) {
	l, _ := newLimiter(t, token.LimiterPolicy{MaxTracked: 100, MaxFailuresPerClient: 1_000_000})
	for i := 0; i < 5000; i++ {
		l.Attempt(ctx, "app", fmt.Sprintf("account-%d", i), fmt.Sprintf("ip-%d", i))
	}
	if n := l.Len(); n > 110 {
		t.Fatalf("the limiter holds %d keys with a cap of 100", n)
	}
}

func TestALockedKeyIsNotEvictedToMakeRoom(t *testing.T) {
	l, _ := newLimiter(t, token.LimiterPolicy{MaxTracked: 10, MaxFailuresPerAccount: 1})
	fail(l, "victim", "ip-victim") // locks
	for i := 0; i < 500; i++ {
		l.Attempt(ctx, "app", fmt.Sprintf("noise-%d", i), fmt.Sprintf("noise-ip-%d", i))
	}
	if _, ok := fail(l, "victim", "other-ip"); ok {
		t.Fatal("a flood of other keys pushed a lockout out of the table")
	}
}

func TestThePolicyRefusesWhatCannotWork(t *testing.T) {
	for name, policy := range map[string]token.LimiterPolicy{
		"a negative budget":     {MaxFailuresPerAccount: -1},
		"a negative window":     {Window: -time.Second},
		"a negative lockout":    {BaseLockout: -time.Second},
		"a cap below the base":  {BaseLockout: time.Hour, MaxLockout: time.Minute},
		"a negative table size": {MaxTracked: -1},
	} {
		if _, err := token.NewLimiter(policy); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := token.NewLimiter(token.LimiterPolicy{}); err != nil {
		t.Errorf("the zero policy was refused: %v", err)
	}
}

func TestGuardRunsTheCheckBehindTheThrottle(t *testing.T) {
	l, _ := newLimiter(t, token.LimiterPolicy{MaxFailuresPerAccount: 2})
	calls := 0
	check := func(ok bool, err error) func(context.Context) (bool, error) {
		return func(context.Context) (bool, error) { calls++; return ok, err }
	}
	guard := func(c func(context.Context) (bool, error)) error {
		return token.Guard(ctx, l, "app", "ana", "ip", c)
	}

	// A wrong password is ErrBadCredentials and stays counted.
	if err := guard(check(false, nil)); !errors.Is(err, token.ErrBadCredentials) {
		t.Fatalf("a wrong password: %v", err)
	}
	// A check that could not run gives the unit back and says what went wrong.
	down := errors.New("the users table is unreachable")
	if err := guard(check(false, down)); !errors.Is(err, down) {
		t.Fatalf("a failing check: %v", err)
	}
	// So only one unit has been spent, and the second wrong password is allowed.
	if err := guard(check(false, nil)); !errors.Is(err, token.ErrBadCredentials) {
		t.Fatalf("a second wrong password: %v", err)
	}
	// Which spent the budget: the check is not even called now.
	before := calls
	err := guard(check(true, nil))
	var locked *token.LockedError
	if !errors.As(err, &locked) || !errors.Is(err, token.ErrTooManyAttempts) || locked.RetryAfter <= 0 {
		t.Fatalf("a locked account: %v, want a LockedError", err)
	}
	if calls != before {
		t.Fatal("the credentials were checked for a locked account")
	}
}

func TestGuardClearsTheAccountOnSuccess(t *testing.T) {
	l, _ := newLimiter(t, token.LimiterPolicy{MaxFailuresPerAccount: 3})
	wrong := func(context.Context) (bool, error) { return false, nil }
	right := func(context.Context) (bool, error) { return true, nil }
	_ = token.Guard(ctx, l, "app", "ana", "ip", wrong)
	_ = token.Guard(ctx, l, "app", "ana", "ip", wrong)
	if err := token.Guard(ctx, l, "app", "ana", "ip", right); err != nil {
		t.Fatalf("the right password: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := token.Guard(ctx, l, "app", "ana", "ip", wrong); errors.Is(err, token.ErrTooManyAttempts) {
			t.Fatal("a good sign-in did not forget the failures before it")
		}
	}
}

func TestGuardWorksOverTheFrameworksOwnThrottle(t *testing.T) {
	memory := auth.NewMemoryThrottle()
	wrong := func(context.Context) (bool, error) { return false, nil }
	var err error
	for i := 0; i < auth.MaxSignInFailures; i++ {
		err = token.Guard(ctx, memory, "app", "ana", "ip", wrong)
	}
	if !errors.Is(err, token.ErrBadCredentials) {
		t.Fatalf("last allowed attempt: %v", err)
	}
	if err := token.Guard(ctx, memory, "app", "ana", "ip", wrong); !errors.Is(err, token.ErrTooManyAttempts) {
		t.Fatalf("over the framework's budget: %v", err)
	}
}
