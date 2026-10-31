package feature_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	token "github.com/hyz-is/arandu-token"
)

var ctx = context.Background()

func TestIssueGivesAPairThatResolves(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		pair := w.issue(t, "ana", "ws-1", "phone-1")

		access, refresh := pair.Access.Reveal(), pair.Refresh.Reveal()
		if !strings.HasPrefix(access, "alpra_") || !strings.HasPrefix(refresh, "alprr_") {
			t.Fatalf("prefixes: access %q refresh %q", access[:6], refresh[:6])
		}
		// 32 random bytes in base64url are 43 characters.
		if len(access) != len("alpra_")+43 || len(refresh) != len("alprr_")+43 {
			t.Fatalf("token lengths %d and %d", len(access), len(refresh))
		}
		if access == refresh {
			t.Fatal("the access and refresh tokens are the same")
		}
		if want := w.clock.Now().Add(15 * time.Minute); !pair.AccessExpires.Equal(want) {
			t.Fatalf("access expires %s, want %s", pair.AccessExpires, want)
		}
		if want := w.clock.Now().Add(60 * 24 * time.Hour); !pair.RefreshExpires.Equal(want) {
			t.Fatalf("refresh expires %s, want %s", pair.RefreshExpires, want)
		}

		p, ok := w.resolves(t, access)
		if !ok {
			t.Fatal("a fresh access token is not accepted")
		}
		if p.UserID != "ana" || p.WorkspaceID != "ws-1" || p.DeviceID != "phone-1" || p.FamilyID == "" {
			t.Fatalf("principal = %+v", p)
		}
		if _, ok := w.resolves(t, refresh); ok {
			t.Fatal("a refresh token is accepted as an access token")
		}
		if _, ok := w.resolves(t, "alpra_nobody-issued-this"); ok {
			t.Fatal("a token nobody issued is accepted")
		}
		if got := w.log.kinds(); len(got) != 1 || got[0] != token.EventIssued {
			t.Fatalf("events = %v", got)
		}
	})
}

func TestTwoIssuesAreIndependentPairs(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		a, b := w.issue(t, "ana", "ws-1", "phone-1"), w.issue(t, "ana", "ws-1", "tablet-1")
		if a.Access.Reveal() == b.Access.Reveal() || a.Refresh.Reveal() == b.Refresh.Reveal() {
			t.Fatal("two sign-ins got the same token")
		}
		if _, ok := w.resolves(t, a.Access.Reveal()); !ok {
			t.Fatal("signing in on a second device ended the first")
		}
	})
}

func TestAnAccessTokenExpires(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		pair := w.issue(t, "ana", "ws-1", "phone-1")

		w.clock.Advance(14*time.Minute + 59*time.Second)
		if _, ok := w.resolves(t, pair.Access.Reveal()); !ok {
			t.Fatal("the access token stopped working before it expired")
		}
		w.clock.Advance(time.Second)
		if _, ok := w.resolves(t, pair.Access.Reveal()); ok {
			t.Fatal("the access token still works after it expired")
		}
		// The refresh token is what outlives it.
		if _, err := w.svc.Refresh(ctx, pair.Refresh.Reveal()); err != nil {
			t.Fatalf("refreshing after the access token expired: %v", err)
		}
	})
}

func TestARefreshTokenExpires(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		pair := w.issue(t, "ana", "ws-1", "phone-1")
		w.clock.Advance(60*24*time.Hour + time.Second)
		if _, err := w.svc.Refresh(ctx, pair.Refresh.Reveal()); !errors.Is(err, token.ErrInvalidToken) {
			t.Fatalf("refreshing an expired token: %v, want ErrInvalidToken", err)
		}
		// An expired token is not a theft.
		if got := w.log.kinds(); len(got) != 1 {
			t.Fatalf("events = %v, an expired refresh recorded something", got)
		}
	})
}

func TestTheLifetimesAreConfigurable(t *testing.T) {
	eachDatabase(t, func(c *token.Config) { c.AccessTTL, c.RefreshTTL = time.Minute, time.Hour }, func(t *testing.T, w *world) {
		pair := w.issue(t, "ana", "ws-1", "phone-1")
		w.clock.Advance(time.Minute)
		if _, ok := w.resolves(t, pair.Access.Reveal()); ok {
			t.Fatal("a one-minute access token survived a minute")
		}
		w.clock.Advance(59*time.Minute - time.Second)
		if _, err := w.svc.Refresh(ctx, pair.Refresh.Reveal()); err != nil {
			t.Fatalf("refresh inside its hour: %v", err)
		}
	})
}

func TestRefreshRotatesThePair(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		first := w.issue(t, "ana", "ws-1", "phone-1")
		w.clock.Advance(10 * time.Minute)

		second, err := w.svc.Refresh(ctx, first.Refresh.Reveal())
		if err != nil {
			t.Fatal(err)
		}
		if second.Access.Reveal() == first.Access.Reveal() || second.Refresh.Reveal() == first.Refresh.Reveal() {
			t.Fatal("the refresh returned a token it already had")
		}
		if want := w.clock.Now().Add(15 * time.Minute); !second.AccessExpires.Equal(want) {
			t.Fatalf("the new access token expires %s, want %s", second.AccessExpires, want)
		}
		p, ok := w.resolves(t, second.Access.Reveal())
		if !ok || p.UserID != "ana" || p.WorkspaceID != "ws-1" || p.DeviceID != "phone-1" {
			t.Fatalf("the new access token resolves to %+v, %v", p, ok)
		}
		// The old access token went with the old pair.
		if _, ok := w.resolves(t, first.Access.Reveal()); ok {
			t.Fatal("the previous access token still works after the exchange")
		}
		// And the refresh token keeps rotating.
		if _, err := w.svc.Refresh(ctx, second.Refresh.Reveal()); err != nil {
			t.Fatalf("second rotation: %v", err)
		}
		if got := w.log.kinds(); len(got) != 3 || got[1] != token.EventRefreshed || got[2] != token.EventRefreshed {
			t.Fatalf("events = %v", got)
		}
	})
}

func TestReusingAnExchangedRefreshTokenRevokesTheFamily(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		first := w.issue(t, "ana", "ws-1", "phone-1")
		second, err := w.svc.Refresh(ctx, first.Refresh.Reveal())
		if err != nil {
			t.Fatal(err)
		}
		w.log.reset()

		// Somebody presents the token that was already exchanged.
		_, err = w.svc.Refresh(ctx, first.Refresh.Reveal())
		if !errors.Is(err, token.ErrReuseDetected) {
			t.Fatalf("reuse answered %v, want ErrReuseDetected", err)
		}

		// Everything of that session is dead, the owner's current pair included.
		if _, ok := w.resolves(t, second.Access.Reveal()); ok {
			t.Fatal("the current access token survived the reuse")
		}
		if _, err := w.svc.Refresh(ctx, second.Refresh.Reveal()); !errors.Is(err, token.ErrInvalidToken) {
			t.Fatalf("the current refresh token after the reuse: %v, want ErrInvalidToken", err)
		}
		got := w.log.kinds()
		if len(got) != 1 || got[0] != token.EventReuseDetected {
			t.Fatalf("events = %v", got)
		}
		if e := w.log.last(); e.UserID != "ana" || e.DeviceID != "phone-1" || e.Reason != token.ReasonReuse || e.FamilyID == "" {
			t.Fatalf("event = %+v", e)
		}
	})
}

func TestAReuseOnOneDeviceLeavesTheOthersAlone(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		phone, tablet := w.issue(t, "ana", "ws-1", "phone-1"), w.issue(t, "ana", "ws-1", "tablet-1")
		other := w.issue(t, "bruno", "ws-1", "phone-1")

		if _, err := w.svc.Refresh(ctx, phone.Refresh.Reveal()); err != nil {
			t.Fatal(err)
		}
		if _, err := w.svc.Refresh(ctx, phone.Refresh.Reveal()); !errors.Is(err, token.ErrReuseDetected) {
			t.Fatalf("reuse: %v", err)
		}
		for name, pair := range map[string]token.Pair{"the same user's other device": tablet, "another user's device of the same name": other} {
			if _, ok := w.resolves(t, pair.Access.Reveal()); !ok {
				t.Fatalf("%s was revoked by a reuse on the phone", name)
			}
		}
	})
}

func TestARevokedRefreshTokenIsRefusedWithoutBeingATheft(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		pair := w.issue(t, "ana", "ws-1", "phone-1")
		if err := w.svc.Revoke(ctx, pair.Access.Reveal()); err != nil {
			t.Fatal(err)
		}
		w.log.reset()
		if _, err := w.svc.Refresh(ctx, pair.Refresh.Reveal()); !errors.Is(err, token.ErrInvalidToken) {
			t.Fatalf("a revoked refresh token: %v, want ErrInvalidToken", err)
		}
		if got := w.log.kinds(); len(got) != 0 {
			t.Fatalf("a revoked token recorded %v", got)
		}
	})
}

func TestRefreshRefusesWhatIsNotARefreshToken(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		pair := w.issue(t, "ana", "ws-1", "phone-1")
		for name, bad := range map[string]string{
			"empty":           "",
			"an access token": pair.Access.Reveal(),
			"never issued":    "alprr_" + strings.Repeat("x", 43),
			"no prefix":       strings.TrimPrefix(pair.Refresh.Reveal(), "alprr_"),
		} {
			if _, err := w.svc.Refresh(ctx, bad); !errors.Is(err, token.ErrInvalidToken) {
				t.Errorf("%s: %v, want ErrInvalidToken", name, err)
			}
		}
		// None of that hurt the real thing.
		if _, err := w.svc.Refresh(ctx, pair.Refresh.Reveal()); err != nil {
			t.Fatalf("the real refresh token after the bad ones: %v", err)
		}
	})
}

func TestTwoSimultaneousRefreshesHaveOneWinner(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		pair := w.issue(t, "ana", "ws-1", "phone-1")
		results := race(w, pair.Refresh.Reveal(), 8)

		var won []token.Pair
		for _, r := range results {
			switch {
			case r.err == nil:
				won = append(won, r.pair)
			case errors.Is(r.err, token.ErrReuseDetected), errors.Is(r.err, token.ErrInvalidToken):
			default:
				t.Fatalf("a simultaneous refresh failed with %v", r.err)
			}
		}
		if len(won) != 1 {
			t.Fatalf("%d of 8 simultaneous refreshes won, want exactly one", len(won))
		}
		// With no grace the losers took the winner's copy for a theft, so the
		// session is gone and the device signs in again. ReuseGrace is how an
		// application that refreshes from parallel requests avoids that.
		if _, ok := w.resolves(t, won[0].Access.Reveal()); ok {
			t.Fatal("the losers saw a reuse and left the winner's pair alive")
		}
	})
}

func TestAReuseGraceKeepsTheWinnersPairAlive(t *testing.T) {
	eachDatabase(t, func(c *token.Config) { c.ReuseGrace = 10 * time.Second }, func(t *testing.T, w *world) {
		pair := w.issue(t, "ana", "ws-1", "phone-1")
		results := race(w, pair.Refresh.Reveal(), 8)

		var won []token.Pair
		for _, r := range results {
			switch {
			case r.err == nil:
				won = append(won, r.pair)
			case errors.Is(r.err, token.ErrInvalidToken):
			default:
				t.Fatalf("inside the grace a loser answered %v, want ErrInvalidToken", r.err)
			}
		}
		if len(won) != 1 {
			t.Fatalf("%d winners, want one", len(won))
		}
		if _, ok := w.resolves(t, won[0].Access.Reveal()); !ok {
			t.Fatal("the winner's pair was revoked by the losers")
		}

		// Outside the grace the same token is a theft.
		w.clock.Advance(11 * time.Second)
		if _, err := w.svc.Refresh(ctx, pair.Refresh.Reveal()); !errors.Is(err, token.ErrReuseDetected) {
			t.Fatalf("a reuse after the grace: %v, want ErrReuseDetected", err)
		}
	})
}

type raced struct {
	pair token.Pair
	err  error
}

// race refreshes one token from n goroutines released together.
func race(w *world, refresh string, n int) []raced {
	var (
		wg      sync.WaitGroup
		start   = make(chan struct{})
		results = make([]raced, n)
	)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results[i].pair, results[i].err = w.svc.Refresh(ctx, refresh)
		}()
	}
	close(start)
	wg.Wait()
	return results
}

func TestRevokeEndsTheWholeSession(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		first := w.issue(t, "ana", "ws-1", "phone-1")
		second, err := w.svc.Refresh(ctx, first.Refresh.Reveal())
		if err != nil {
			t.Fatal(err)
		}
		other := w.issue(t, "ana", "ws-1", "tablet-1")
		w.log.reset()

		if err := w.svc.Revoke(ctx, second.Access.Reveal()); err != nil {
			t.Fatal(err)
		}
		if _, ok := w.resolves(t, second.Access.Reveal()); ok {
			t.Fatal("a revoked access token still works")
		}
		if _, err := w.svc.Refresh(ctx, second.Refresh.Reveal()); !errors.Is(err, token.ErrInvalidToken) {
			t.Fatalf("the refresh token of a revoked session: %v", err)
		}
		if _, ok := w.resolves(t, other.Access.Reveal()); !ok {
			t.Fatal("signing out of the phone signed out the tablet")
		}
		if e := w.log.last(); e.Kind != token.EventRevoked || e.Reason != token.ReasonSignedOut || e.DeviceID != "phone-1" {
			t.Fatalf("event = %+v", e)
		}

		// A refresh token revokes the session as well, and a second sign-out, or
		// one with a token nobody knows, is not an error.
		third := w.issue(t, "ana", "ws-1", "phone-1")
		if err := w.svc.Revoke(ctx, third.Refresh.Reveal()); err != nil {
			t.Fatal(err)
		}
		if _, ok := w.resolves(t, third.Access.Reveal()); ok {
			t.Fatal("revoking by the refresh token left the access token alive")
		}
		for _, again := range []string{third.Access.Reveal(), "alpra_never-issued", "garbage", ""} {
			if err := w.svc.Revoke(ctx, again); err != nil {
				t.Fatalf("Revoke(%.8q): %v", again, err)
			}
		}
	})
}

func TestRevokeDeviceIsScopedToTheUser(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		ana := w.issue(t, "ana", "ws-1", "phone-1")
		bruno := w.issue(t, "bruno", "ws-1", "phone-1")
		w.log.reset()

		// The same device name on another account is another device.
		if err := w.svc.RevokeDevice(ctx, "ana", "phone-1"); err != nil {
			t.Fatal(err)
		}
		if _, ok := w.resolves(t, ana.Access.Reveal()); ok {
			t.Fatal("the device was not revoked")
		}
		if _, ok := w.resolves(t, bruno.Access.Reveal()); !ok {
			t.Fatal("revoking Ana's phone revoked Bruno's")
		}
		if e := w.log.last(); e.Kind != token.EventRevoked || e.Reason != token.ReasonDeviceRemoved || e.UserID != "ana" {
			t.Fatalf("event = %+v", e)
		}

		// Nothing left on that device, and a device that is not the user's, are the
		// same answer.
		for name, args := range map[string][2]string{
			"already revoked":           {"ana", "phone-1"},
			"never existed":             {"ana", "ghost"},
			"another user's device id":  {"carla", "phone-1"},
			"a user with no device yet": {"nobody", "phone-1"},
		} {
			if err := w.svc.RevokeDevice(ctx, args[0], args[1]); !errors.Is(err, token.ErrNotFound) {
				t.Errorf("%s: %v, want ErrNotFound", name, err)
			}
		}
		if _, ok := w.resolves(t, bruno.Access.Reveal()); !ok {
			t.Fatal("a refused revocation touched another user")
		}
	})
}

func TestRevokeAllForUserEndsEveryDeviceOfThatUserOnly(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		a1, a2 := w.issue(t, "ana", "ws-1", "phone-1"), w.issue(t, "ana", "ws-2", "tablet-1")
		b1 := w.issue(t, "bruno", "ws-1", "phone-1")
		w.log.reset()

		n, err := w.svc.RevokeAllForUser(ctx, "ana")
		if err != nil || n != 2 {
			t.Fatalf("RevokeAllForUser = %d, %v; want 2", n, err)
		}
		for _, pair := range []token.Pair{a1, a2} {
			if _, ok := w.resolves(t, pair.Access.Reveal()); ok {
				t.Fatal("a device of the user survived")
			}
			if _, err := w.svc.Refresh(ctx, pair.Refresh.Reveal()); !errors.Is(err, token.ErrInvalidToken) {
				t.Fatalf("a refresh token of the user survived: %v", err)
			}
		}
		if _, ok := w.resolves(t, b1.Access.Reveal()); !ok {
			t.Fatal("signing Ana out everywhere signed Bruno out")
		}
		if got := w.log.kinds(); len(got) != 2 || got[0] != token.EventRevoked {
			t.Fatalf("events = %v, want one revoked per device", got)
		}
		if e := w.log.last(); e.Reason != token.ReasonAllDevices {
			t.Fatalf("reason = %q", e.Reason)
		}

		if n, err := w.svc.RevokeAllForUser(ctx, "ana"); err != nil || n != 0 {
			t.Fatalf("a second RevokeAllForUser = %d, %v; want 0", n, err)
		}
	})
}

func TestSwitchBindsANewPairToTheNewWorkspace(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		old := w.issue(t, "ana", "ws-1", "phone-1")
		w.log.reset()

		pair, err := w.svc.Switch(ctx, old.Access.Reveal(), "ws-2")
		if err != nil {
			t.Fatal(err)
		}
		p, ok := w.resolves(t, pair.Access.Reveal())
		if !ok || p.WorkspaceID != "ws-2" || p.UserID != "ana" || p.DeviceID != "phone-1" {
			t.Fatalf("the new token resolves to %+v, %v", p, ok)
		}
		if pair.WorkspaceID != "ws-2" {
			t.Fatalf("pair workspace = %q", pair.WorkspaceID)
		}
		// The old pair is gone, so a client that keeps using it is refused.
		if _, ok := w.resolves(t, old.Access.Reveal()); ok {
			t.Fatal("the old access token still works")
		}
		if _, err := w.svc.Refresh(ctx, old.Refresh.Reveal()); !errors.Is(err, token.ErrInvalidToken) {
			t.Fatalf("the old refresh token after a switch: %v, want ErrInvalidToken", err)
		}
		// The new refresh token keeps the new workspace through rotations.
		next, err := w.svc.Refresh(ctx, pair.Refresh.Reveal())
		if err != nil {
			t.Fatal(err)
		}
		if p, _ := w.resolves(t, next.Access.Reveal()); p.WorkspaceID != "ws-2" {
			t.Fatalf("after a refresh the workspace is %q", p.WorkspaceID)
		}
		if got := w.log.kinds(); got[0] != token.EventSwitched {
			t.Fatalf("events = %v", got)
		}
	})
}

func TestSwitchRefusesWhatIsNotALiveAccessToken(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		pair := w.issue(t, "ana", "ws-1", "phone-1")
		for name, bad := range map[string]string{
			"a refresh token": pair.Refresh.Reveal(),
			"nothing":         "",
			"never issued":    "alpra_" + strings.Repeat("y", 43),
		} {
			if _, err := w.svc.Switch(ctx, bad, "ws-2"); !errors.Is(err, token.ErrInvalidToken) {
				t.Errorf("%s: %v, want ErrInvalidToken", name, err)
			}
		}
		w.clock.Advance(16 * time.Minute)
		if _, err := w.svc.Switch(ctx, pair.Access.Reveal(), "ws-2"); !errors.Is(err, token.ErrInvalidToken) {
			t.Errorf("an expired access token: %v, want ErrInvalidToken", err)
		}
		if _, err := w.svc.Switch(ctx, pair.Access.Reveal(), "bad workspace!"); err == nil {
			t.Error("a workspace identifier with a space and a bang was accepted")
		}
	})
}

func TestTwoSimultaneousSwitchesHaveOneWinner(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		pair := w.issue(t, "ana", "ws-1", "phone-1")
		var (
			wg    sync.WaitGroup
			start = make(chan struct{})
			errs  = make([]error, 6)
		)
		for i := range errs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, errs[i] = w.svc.Switch(ctx, pair.Access.Reveal(), "ws-2")
			}()
		}
		close(start)
		wg.Wait()
		won := 0
		for _, err := range errs {
			switch {
			case err == nil:
				won++
			case errors.Is(err, token.ErrInvalidToken):
			default:
				t.Fatalf("a simultaneous switch failed with %v", err)
			}
		}
		if won != 1 {
			t.Fatalf("%d switches won, want one", won)
		}
		if n := w.count(t, `SELECT count(*) FROM token_credentials WHERE revoked_at IS NULL AND kind = 'access'`); n != 1 {
			t.Fatalf("%d live access tokens after the race, want one", n)
		}
	})
}

func TestSigningInAgainOnADeviceReplacesItsSession(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		old := w.issue(t, "ana", "ws-1", "phone-1")
		w.log.reset()
		fresh := w.issue(t, "ana", "ws-1", "phone-1")

		if _, ok := w.resolves(t, old.Access.Reveal()); ok {
			t.Fatal("the previous session of the device still works")
		}
		if _, ok := w.resolves(t, fresh.Access.Reveal()); !ok {
			t.Fatal("the new session does not work")
		}
		devices, err := w.svc.ListDevices(ctx, "ana")
		if err != nil || len(devices) != 1 {
			t.Fatalf("devices = %v, %v; want one", devices, err)
		}
		got := w.log.kinds()
		if len(got) != 2 || got[0] != token.EventRevoked || got[1] != token.EventIssued {
			t.Fatalf("events = %v", got)
		}
		if w.log.events[0].Reason != token.ReasonReplaced {
			t.Fatalf("reason = %q", w.log.events[0].Reason)
		}
	})
}

func TestListDevicesShowsNamePlatformLastUseAndAddress(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		phone, err := w.svc.Issue(token.WithClientIP(ctx, "203.0.113.7"), "ana", "ws-1", token.Device{ID: "phone-1", Name: "Pixel de Ana", Platform: "android"})
		if err != nil {
			t.Fatal(err)
		}
		w.clock.Advance(time.Hour)
		if _, err := w.svc.Issue(ctx, "ana", "ws-1", token.Device{ID: "mac-1", Name: "MacBook", Platform: "macos"}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.svc.Issue(ctx, "bruno", "ws-1", token.Device{ID: "phone-1", Name: "Pixel do Bruno", Platform: "android"}); err != nil {
			t.Fatal(err)
		}

		devices, err := w.svc.ListDevices(ctx, "ana")
		if err != nil {
			t.Fatal(err)
		}
		if len(devices) != 2 || devices[0].ID != "mac-1" || devices[1].ID != "phone-1" {
			t.Fatalf("devices = %+v, want the most recently used first", devices)
		}
		got := devices[1]
		if got.Name != "Pixel de Ana" || got.Platform != "android" || got.LastIP != "203.0.113.7" {
			t.Fatalf("device = %+v", got)
		}
		if want := w.clock.Now().Add(-time.Hour); !got.LastUsedAt.Equal(want) || !got.CreatedAt.Equal(want) {
			t.Fatalf("last use %s created %s, want %s", got.LastUsedAt, got.CreatedAt, want)
		}

		// A device whose session ended is not a place the user is signed in.
		if err := w.svc.Revoke(ctx, phone.Access.Reveal()); err != nil {
			t.Fatal(err)
		}
		if devices, _ := w.svc.ListDevices(ctx, "ana"); len(devices) != 1 || devices[0].ID != "mac-1" {
			t.Fatalf("after a sign-out devices = %+v", devices)
		}
		// And one whose refresh token expired is not either.
		w.clock.Advance(61 * 24 * time.Hour)
		if devices, _ := w.svc.ListDevices(ctx, "ana"); len(devices) != 0 {
			t.Fatalf("after the refresh tokens expired devices = %+v", devices)
		}
		if devices, err := w.svc.ListDevices(ctx, "nobody"); err != nil || devices == nil || len(devices) != 0 {
			t.Fatalf("a user with no device: %v, %v; want an empty list", devices, err)
		}
	})
}

func TestResolveRecordsTheUseWithoutWritingOnEveryRequest(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		pair := w.issue(t, "ana", "ws-1", "phone-1")
		at := func() time.Time {
			devices, err := w.svc.ListDevices(ctx, "ana")
			if err != nil || len(devices) != 1 {
				t.Fatalf("devices = %v, %v", devices, err)
			}
			return devices[0].LastUsedAt
		}
		ip := func() string {
			devices, _ := w.svc.ListDevices(ctx, "ana")
			return devices[0].LastIP
		}
		issued := at()

		// Inside the touch interval nothing is written, whatever the address.
		w.clock.Advance(10 * time.Second)
		if _, ok, err := w.svc.Resolve(token.WithClientIP(ctx, "198.51.100.1"), token.DigestOf(pair.Access.Reveal())); !ok || err != nil {
			t.Fatal(ok, err)
		}
		if got := at(); !got.Equal(issued) {
			t.Fatalf("a request inside the interval moved the last use to %s", got)
		}

		// The first one after it is written, and so is its address.
		w.clock.Advance(time.Minute)
		if _, ok, err := w.svc.Resolve(token.WithClientIP(ctx, "198.51.100.2"), token.DigestOf(pair.Access.Reveal())); !ok || err != nil {
			t.Fatal(ok, err)
		}
		if got := at(); !got.Equal(w.clock.Now()) {
			t.Fatalf("last use = %s, want %s", got, w.clock.Now())
		}
		if got := ip(); got != "198.51.100.2" {
			t.Fatalf("last address = %q", got)
		}

		// A request that carries no address does not erase the last one.
		w.clock.Advance(time.Minute)
		if _, ok := w.resolves(t, pair.Access.Reveal()); !ok {
			t.Fatal("resolve")
		}
		if got := ip(); got != "198.51.100.2" {
			t.Fatalf("a request with no address replaced it with %q", got)
		}
	})
}

func TestCleanDeletesWhatExpiredOrWasRevokedBeforeTheRetention(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		gone := w.issue(t, "ana", "ws-1", "gone")
		if err := w.svc.Revoke(ctx, gone.Access.Reveal()); err != nil {
			t.Fatal(err)
		}
		live := w.issue(t, "ana", "ws-1", "live")

		// Inside the retention nothing is deleted.
		w.clock.Advance(6 * 24 * time.Hour)
		if got, err := w.svc.Clean(ctx); err != nil || got.Credentials != 0 || got.Devices != 0 {
			t.Fatalf("Clean inside the retention = %+v, %v", got, err)
		}

		// After it the revoked session is deleted, and the live one stays: its
		// access token expired days ago and is deleted, its refresh token is not.
		w.clock.Advance(2 * 24 * time.Hour)
		got, err := w.svc.Clean(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if got.Credentials != 3 {
			t.Fatalf("Clean deleted %d credentials, want 3 (the revoked pair and the expired access token)", got.Credentials)
		}
		if n := w.count(t, `SELECT count(*) FROM token_credentials WHERE kind = 'refresh'`); n != 1 {
			t.Fatalf("%d refresh tokens left, want the live one", n)
		}
		if _, err := w.svc.Refresh(ctx, live.Refresh.Reveal()); err != nil {
			t.Fatalf("the live session after the clean: %v", err)
		}
		if devices, _ := w.svc.ListDevices(ctx, "ana"); len(devices) != 1 || devices[0].ID != "live" {
			t.Fatalf("devices = %+v", devices)
		}
		// The device of the deleted session had no credential left and had not been
		// seen since the retention, so it went with them.
		if got.Devices != 1 {
			t.Fatalf("Clean deleted %d devices, want 1", got.Devices)
		}
		if n := w.count(t, `SELECT count(*) FROM token_devices`); n != 1 {
			t.Fatalf("%d device rows, want the live one", n)
		}

		// Past the refresh lifetime and the retention everything goes, devices too.
		w.clock.Advance(70 * 24 * time.Hour)
		if _, err := w.svc.Clean(ctx); err != nil {
			t.Fatal(err)
		}
		if n := w.count(t, `SELECT count(*) FROM token_credentials`); n != 0 {
			t.Fatalf("%d credentials left", n)
		}
		if n := w.count(t, `SELECT count(*) FROM token_devices`); n != 0 {
			t.Fatalf("%d devices left", n)
		}
	})
}

func TestAnExchangedTokenIsRecognisedUntilTheCleanForgetsIt(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		first := w.issue(t, "ana", "ws-1", "phone-1")
		if _, err := w.svc.Refresh(ctx, first.Refresh.Reveal()); err != nil {
			t.Fatal(err)
		}
		// Past the retention the exchanged token is deleted, and a copy of it is
		// a token nobody has heard of rather than a theft.
		w.clock.Advance(8 * 24 * time.Hour)
		if _, err := w.svc.Clean(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := w.svc.Refresh(ctx, first.Refresh.Reveal()); !errors.Is(err, token.ErrInvalidToken) {
			t.Fatalf("an exchanged token after the clean: %v, want ErrInvalidToken", err)
		}
	})
}

func TestTheRecorderRunsInsideTheActAndFailsIt(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		w.log.fail = errors.New("the log is down")
		if _, err := w.svc.Issue(ctx, "ana", "ws-1", token.Device{ID: "phone-1"}); err == nil || !strings.Contains(err.Error(), "the log is down") {
			t.Fatalf("Issue with a failing recorder: %v", err)
		}
		if n := w.count(t, `SELECT count(*) FROM token_credentials`); n != 0 {
			t.Fatalf("%d credentials survived an act the log refused", n)
		}

		w.log.fail = nil
		pair := w.issue(t, "ana", "ws-1", "phone-1")
		w.log.fail = errors.New("the log is down")
		if _, err := w.svc.Refresh(ctx, pair.Refresh.Reveal()); err == nil {
			t.Fatal("Refresh succeeded with a failing recorder")
		}
		// The failed exchange was rolled back with it: the token still works.
		w.log.fail = nil
		if _, err := w.svc.Refresh(ctx, pair.Refresh.Reveal()); err != nil {
			t.Fatalf("a refresh token spent by an act that rolled back: %v", err)
		}
	})
}

func TestAnIdentifierThatCannotBeStoredIsRefused(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		long := strings.Repeat("a", 65)
		for name, call := range map[string]func() error{
			"empty user":        func() error { _, err := w.svc.Issue(ctx, "", "ws", token.Device{ID: "d"}); return err },
			"user with a space": func() error { _, err := w.svc.Issue(ctx, "a b", "ws", token.Device{ID: "d"}); return err },
			"user too long":     func() error { _, err := w.svc.Issue(ctx, long, "ws", token.Device{ID: "d"}); return err },
			"user with a quote": func() error {
				_, err := w.svc.Issue(ctx, "a'; DROP TABLE x;--", "ws", token.Device{ID: "d"})
				return err
			},
			"workspace too long": func() error { _, err := w.svc.Issue(ctx, "ana", long, token.Device{ID: "d"}); return err },
			"no device":          func() error { _, err := w.svc.Issue(ctx, "ana", "ws", token.Device{}); return err },
			"device with a slash": func() error {
				_, err := w.svc.Issue(ctx, "ana", "ws", token.Device{ID: "a/b"})
				return err
			},
			"revoke device, no user": func() error { return w.svc.RevokeDevice(ctx, "", "d") },
			"revoke all, no user":    func() error { _, err := w.svc.RevokeAllForUser(ctx, ""); return err },
			"list, no user":          func() error { _, err := w.svc.ListDevices(ctx, ""); return err },
		} {
			if err := call(); err == nil {
				t.Errorf("%s was accepted", name)
			}
		}
		if n := w.count(t, `SELECT count(*) FROM token_credentials`); n != 0 {
			t.Fatalf("%d credentials were written for refused input", n)
		}
	})
}

func TestADeviceNameIsCleanedAndNotRefused(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		name := "  Pixel\x00 de\nAna " + strings.Repeat("ã", 200)
		if _, err := w.svc.Issue(ctx, "ana", "", token.Device{ID: "phone-1", Name: name, Platform: strings.Repeat("p", 99)}); err != nil {
			t.Fatal(err)
		}
		devices, err := w.svc.ListDevices(ctx, "ana")
		if err != nil || len(devices) != 1 {
			t.Fatal(devices, err)
		}
		if got := devices[0].Name; len([]rune(got)) != 120 || strings.ContainsAny(got, "\x00\n") || !strings.HasPrefix(got, "Pixel de Ana") {
			t.Fatalf("name = %q", got)
		}
		if len(devices[0].Platform) != 32 {
			t.Fatalf("platform = %q", devices[0].Platform)
		}
	})
}

func TestASessionCanBeBoundToNoWorkspaceYet(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		pair := w.issue(t, "ana", "", "phone-1")
		p, ok := w.resolves(t, pair.Access.Reveal())
		if !ok || p.WorkspaceID != "" {
			t.Fatalf("principal = %+v, %v", p, ok)
		}
		bound, err := w.svc.Switch(ctx, pair.Access.Reveal(), "ws-1")
		if err != nil {
			t.Fatal(err)
		}
		if p, _ := w.resolves(t, bound.Access.Reveal()); p.WorkspaceID != "ws-1" {
			t.Fatalf("principal = %+v", p)
		}
	})
}
