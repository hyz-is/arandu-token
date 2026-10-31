package feature_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/arandu-io/framework/http/middleware"
	"github.com/arandu-io/framework/security"
	"github.com/arandu-io/hesape/auth"

	token "github.com/hyz-is/arandu-token"
)

// answer is what the handler behind the middleware reports about the request.
func answer(w http.ResponseWriter, r *http.Request) {
	subject, _ := auth.SubjectFrom(r.Context())
	p, ok := token.PrincipalFrom(r.Context())
	_, _ = fmt.Fprintf(w, "subject=%s tenant=%s principal=%v user=%s workspace=%s device=%s ip=%s",
		subject.ID, subject.Tenant, ok, p.UserID, p.WorkspaceID, p.DeviceID, token.ClientIPFrom(r.Context()))
}

// memberships is the application's workspaces: who belongs to which.
type memberships map[string][]string

// subjectFor is what an application writes: it revalidates the membership, and
// the Subject's tenant is the workspace it found, not the one in the token.
func (m memberships) subjectFor(_ context.Context, p token.Principal) (security.Subject, error) {
	for _, ws := range m[p.UserID] {
		if ws == p.WorkspaceID {
			return security.Subject{ID: p.UserID, Tenant: ws, Verified: true}, nil
		}
	}
	return security.Subject{}, token.ErrUnknownToken
}

func request(handler http.Handler, authorization, target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.RemoteAddr = "203.0.113.9:51234"
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestARequestWithAValidTokenCarriesTheSubjectAndThePrincipal(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		pair := w.issue(t, "ana", "ws-1", "phone-1")
		app := memberships{"ana": {"ws-1", "ws-2"}}
		handler := w.svc.RequireToken(app.subjectFor)(http.HandlerFunc(answer))

		rec := request(handler, "Bearer "+pair.Access.Reveal(), "/painel")
		want := "subject=ana tenant=ws-1 principal=true user=ana workspace=ws-1 device=phone-1 ip=203.0.113.9"
		if rec.Code != http.StatusOK || rec.Body.String() != want {
			t.Fatalf("%d %q, want 200 %q", rec.Code, rec.Body.String(), want)
		}
		// The scheme is not case sensitive, and surrounding space is trimmed.
		if rec := request(handler, "bearer  "+pair.Access.Reveal()+" ", "/painel"); rec.Code != http.StatusOK {
			t.Fatalf("lower-case scheme: %d", rec.Code)
		}
		// The address was recorded on the device by the request.
		w.clock.Advance(2 * time.Minute)
		request(handler, "Bearer "+pair.Access.Reveal(), "/painel")
		if devices, _ := w.svc.ListDevices(ctx, "ana"); len(devices) != 1 || devices[0].LastIP != "203.0.113.9" {
			t.Fatalf("devices = %+v", devices)
		}
	})
}

func TestEveryRefusedTokenGetsTheSame401(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		pair := w.issue(t, "ana", "ws-1", "phone-1")
		revoked := w.issue(t, "ana", "ws-1", "tablet-1")
		if err := w.svc.Revoke(ctx, revoked.Access.Reveal()); err != nil {
			t.Fatal(err)
		}
		expired := w.issue(t, "ana", "ws-1", "old-1")
		w.clock.Advance(16 * time.Minute)
		current := w.issue(t, "ana", "ws-1", "phone-1")

		// Bruno lost his membership of ws-1 after the token was issued.
		gone := w.issue(t, "bruno", "ws-1", "phone-1")
		app := memberships{"ana": {"ws-1"}, "bruno": {"ws-9"}}
		handler := w.svc.RequireToken(app.subjectFor)(http.HandlerFunc(answer))

		cases := map[string]string{
			"no header":            "",
			"another scheme":       "Basic " + current.Access.Reveal(),
			"a token nobody made":  "Bearer alpra_" + strings.Repeat("z", 43),
			"the wrong prefix":     "Bearer xyz_" + strings.Repeat("z", 43),
			"a refresh token":      "Bearer " + current.Refresh.Reveal(),
			"a revoked token":      "Bearer " + revoked.Access.Reveal(),
			"an expired token":     "Bearer " + expired.Access.Reveal(),
			"a replaced session":   "Bearer " + pair.Access.Reveal(),
			"a lost membership":    "Bearer " + gone.Access.Reveal(),
			"an empty bearer":      "Bearer ",
			"the token in a query": "",
		}
		var first string
		for name, header := range cases {
			target := "/painel"
			if name == "the token in a query" {
				target += "?access_token=" + current.Access.Reveal()
			}
			rec := request(handler, header, target)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%s: %d, want 401", name, rec.Code)
				continue
			}
			if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
				t.Errorf("%s: WWW-Authenticate = %q", name, got)
			}
			// Not one of them says which it was.
			if first == "" {
				first = rec.Body.String()
			} else if rec.Body.String() != first {
				t.Errorf("%s: the body differs from the others: %q vs %q", name, rec.Body.String(), first)
			}
		}
		// The good one is still good after all of that.
		if rec := request(handler, "Bearer "+current.Access.Reveal(), "/painel"); rec.Code != http.StatusOK {
			t.Fatalf("the valid token after the refused ones: %d", rec.Code)
		}
	})
}

func TestTheMembershipIsRevalidatedOnEveryRequest(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		pair := w.issue(t, "ana", "ws-1", "phone-1")
		app := memberships{"ana": {"ws-1"}}
		handler := w.svc.RequireToken(app.subjectFor)(http.HandlerFunc(answer))

		if rec := request(handler, "Bearer "+pair.Access.Reveal(), "/"); rec.Code != http.StatusOK {
			t.Fatalf("while she belongs: %d", rec.Code)
		}
		// She is removed from the workspace. Nothing about the token changed.
		app["ana"] = nil
		if rec := request(handler, "Bearer "+pair.Access.Reveal(), "/"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("after she was removed: %d, want 401", rec.Code)
		}
		app["ana"] = []string{"ws-1"}
		if rec := request(handler, "Bearer "+pair.Access.Reveal(), "/"); rec.Code != http.StatusOK {
			t.Fatalf("after she was added back: %d", rec.Code)
		}
	})
}

func TestAnApplicationFailureIsNotA401(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		pair := w.issue(t, "ana", "ws-1", "phone-1")
		down := errors.New("the workspaces service is down")
		handler := w.svc.RequireToken(func(context.Context, token.Principal) (security.Subject, error) {
			return security.Subject{}, down
		})(http.HandlerFunc(answer))

		defer func() {
			recovered := recover()
			err, ok := recovered.(error)
			if !ok || !errors.Is(err, down) {
				t.Fatalf("recovered %v, want a panic carrying the application's error", recovered)
			}
		}()
		request(handler, "Bearer "+pair.Access.Reveal(), "/")
		t.Fatal("an application failure was answered instead of reaching the recover middleware")
	})
}

func TestASubjectOfAnotherUserIsRefusedAsAWiringMistake(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		pair := w.issue(t, "ana", "ws-1", "phone-1")
		handler := w.svc.RequireToken(func(context.Context, token.Principal) (security.Subject, error) {
			return security.Subject{ID: "bruno", Tenant: "ws-1"}, nil
		})(http.HandlerFunc(answer))

		defer func() {
			if recover() == nil {
				t.Fatal("a Subject that is not the token's user was let through")
			}
		}()
		request(handler, "Bearer "+pair.Access.Reveal(), "/")
	})
}

func TestTheServiceSatisfiesTheFrameworksTokenResolver(t *testing.T) {
	eachDatabase(t, nil, func(t *testing.T, w *world) {
		pair := w.issue(t, "ana", "ws-1", "phone-1")
		app := memberships{"ana": {"ws-1"}}

		// An application that mounts the framework's middleware itself.
		var resolver middleware.TokenResolver = w.svc.Resolver(app.subjectFor)
		handler := middleware.RequireToken(resolver)(http.HandlerFunc(answer))

		rec := request(handler, "Bearer "+pair.Access.Reveal(), "/")
		if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Body.String(), "subject=ana tenant=ws-1") {
			t.Fatalf("%d %q", rec.Code, rec.Body.String())
		}
		if rec := request(handler, "Bearer alpra_"+strings.Repeat("q", 43), "/"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("a token nobody issued: %d", rec.Code)
		}

		// The resolver answers ErrUnknownToken itself for a digest that fails.
		_, err := resolver.ResolveToken(ctx, token.DigestOf("alpra_"+strings.Repeat("q", 43)))
		if !errors.Is(err, middleware.ErrUnknownToken) {
			t.Fatalf("ResolveToken = %v, want ErrUnknownToken", err)
		}
	})
}

func TestAPrincipalCannotBeForgedOntoAContext(t *testing.T) {
	// PrincipalFrom reads a key nothing outside the package can write, so a
	// context that did not pass through RequireToken carries none.
	if _, ok := token.PrincipalFrom(context.Background()); ok {
		t.Fatal("an empty context has a principal")
	}
	if _, ok := token.PrincipalFrom(context.WithValue(context.Background(), "principal", token.Principal{UserID: "ana"})); ok {
		t.Fatal("a string key forged a principal")
	}
}

func TestRemoteIPNeverReadsAForwardedHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.10:4000"
	req.Header.Set("X-Forwarded-For", "6.6.6.6")
	if got := token.RemoteIP(req); got != "192.0.2.10" {
		t.Fatalf("RemoteIP = %q", got)
	}
	req.RemoteAddr = "[2001:db8::1]:4000"
	if got := token.RemoteIP(req); got != "2001:db8::1" {
		t.Fatalf("RemoteIP = %q", got)
	}
}

func TestTheStatusEachErrorIsAnsweredWith(t *testing.T) {
	type statuser interface{ HTTPStatus() int }
	for err, want := range map[error]int{
		token.ErrInvalidToken:                  http.StatusUnauthorized,
		token.ErrReuseDetected:                 http.StatusUnauthorized,
		token.ErrBadCredentials:                http.StatusUnauthorized,
		token.ErrNotFound:                      http.StatusNotFound,
		&token.LockedError{}:                   http.StatusTooManyRequests,
		fmt.Errorf("w: %w", token.ErrNotFound): http.StatusNotFound,
	} {
		var s statuser
		if !errors.As(err, &s) || s.HTTPStatus() != want {
			t.Errorf("%v answers %v, want %d", err, s, want)
		}
	}
	locked := &token.LockedError{RetryAfter: 90*time.Second + time.Millisecond}
	if !errors.Is(locked, token.ErrTooManyAttempts) || locked.GetHeaders().Get("Retry-After") != "91" {
		t.Fatalf("locked error = %v %v", locked, locked.GetHeaders())
	}
}
