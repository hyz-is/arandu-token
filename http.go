package token

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/arandu-io/framework/http/middleware"
	"github.com/arandu-io/framework/security"
)

// ErrUnknownToken is the error a SubjectFunc answers when the principal is no
// longer somebody the application will act for: the membership was removed, the
// account was suspended. RequireToken answers it with the same 401 as a token
// nobody issued.
var ErrUnknownToken = middleware.ErrUnknownToken

// contextKey is the type of the keys this package puts on a context, so that
// no other package's key can collide with them.
type contextKey int

const (
	clientIPKey contextKey = iota
	authenticatedKey
)

// WithClientIP returns a context that carries the address of the request being
// served. Issue, Refresh, Switch, the revocations and Resolve record it on the
// events and on the device. RequireToken sets it from the request, and an
// application's sign-in handler sets it with RemoteIP before calling Issue.
func WithClientIP(ctx context.Context, ip string) context.Context {
	ip = strings.TrimSpace(ip)
	if len(ip) > maxIPLen {
		ip = ip[:maxIPLen]
	}
	return context.WithValue(ctx, clientIPKey, ip)
}

// ClientIPFrom returns the address WithClientIP put on the context, or empty.
func ClientIPFrom(ctx context.Context) string { return clientIP(ctx) }

func clientIP(ctx context.Context) string {
	ip, _ := ctx.Value(clientIPKey).(string)
	return ip
}

// RemoteIP returns the address the connection came from, without the port.
//
// It reads RemoteAddr and never X-Forwarded-For, which the client writes. An
// application behind a proxy rewrites RemoteAddr with its trusted-proxy
// middleware before this runs; without that, every request comes from the
// proxy and the address means nothing.
func RemoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// authenticated is a principal together with the digest it was resolved from.
// The digest is what lets the framework's resolver, which is handed one, check
// that the principal on the context is the one for that token.
type authenticated struct {
	principal Principal
	digest    Digest
}

// PrincipalFrom returns who the access token of the current request was issued
// to, as RequireToken resolved it, including the device, which the framework's
// Subject has no place for.
//
// ok is false on a request RequireToken did not let through. Nothing outside
// this package can put a principal on a context.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	a, ok := ctx.Value(authenticatedKey).(authenticated)
	return a.principal, ok
}

// SubjectFunc turns the principal of a valid token into the Subject the request
// acts as. It is where the application revalidates the membership.
//
// The workspace in the principal is a candidate. The function checks that the
// user still belongs to it, with the application's own service for workspaces,
// and answers the Subject scoped to that workspace, with the roles and actions
// arandu-permission gives it there. When there is no such membership, or the
// account may no longer act, it answers ErrUnknownToken and the request is a
// 401. Any other error means the application could not answer, and the request
// is a 500, not a 401.
//
// The Subject it answers has the principal's UserID as its ID. The Grant that
// reads and writes data comes from security.Authorize on that Subject, as on
// any request.
type SubjectFunc func(ctx context.Context, p Principal) (security.Subject, error)

// Resolver returns the framework's TokenResolver over this service: the digest
// is resolved, and subjectFor turns the principal into a Subject. It is for an
// application that mounts middleware.RequireToken itself; RequireToken below
// does the same and also makes the principal, with the device, available.
func (s *Service) Resolver(subjectFor SubjectFunc) middleware.TokenResolver {
	return resolver{service: s, subjectFor: subjectFor}
}

type resolver struct {
	service    *Service
	subjectFor SubjectFunc
}

var _ middleware.TokenResolver = resolver{}

// ResolveToken resolves the digest and asks the application for the Subject.
func (r resolver) ResolveToken(ctx context.Context, digest middleware.TokenDigest) (security.Subject, error) {
	p, ok, err := r.service.Resolve(ctx, digest)
	if err != nil {
		return security.Subject{}, err
	}
	if !ok {
		return security.Subject{}, ErrUnknownToken
	}
	return subjectOf(ctx, r.subjectFor, p)
}

// carried is the resolver RequireToken hands the framework: the digest was
// already resolved by the layer around it, and the principal is on the context.
type carried struct{ subjectFor SubjectFunc }

var _ middleware.TokenResolver = carried{}

// ResolveToken asks the application for the Subject of the principal the
// request carries, provided it was resolved from this very digest.
func (c carried) ResolveToken(ctx context.Context, digest middleware.TokenDigest) (security.Subject, error) {
	a, ok := ctx.Value(authenticatedKey).(authenticated)
	if !ok || a.digest != digest {
		return security.Subject{}, ErrUnknownToken
	}
	return subjectOf(ctx, c.subjectFor, a.principal)
}

// subjectOf asks the application for the Subject and holds it to being the
// user the token was issued to.
func subjectOf(ctx context.Context, subjectFor SubjectFunc, p Principal) (security.Subject, error) {
	subject, err := subjectFor(ctx, p)
	if err != nil {
		if errors.Is(err, ErrUnknownToken) {
			return security.Subject{}, ErrUnknownToken
		}
		return security.Subject{}, fmt.Errorf("token: the application could not answer the subject of a token: %w", err)
	}
	if subject.ID != p.UserID {
		return security.Subject{}, errors.New("token: SubjectFunc answered a subject that is not the user the token was issued to")
	}
	return subject, nil
}

// RequireToken lets a request through when it carries a valid access token as
// Authorization: Bearer, and puts on its context the Subject subjectFor
// answered, where ctx.User and auth.SubjectFrom read it, and the Principal,
// where PrincipalFrom reads it.
//
// It is the framework's middleware.RequireToken with this service as the
// store: a request with no token, with a token nobody issued, with one that
// expired or was revoked, or whose subjectFor says the user no longer belongs,
// is answered the same 401 with WWW-Authenticate: Bearer. A token is read from
// the header and from nowhere else. The store failing to answer is not a 401: it
// panics, as the framework's does, and reaches the application's recover
// middleware as a 500.
//
// The address of the request, from RemoteAddr, goes on the context for the
// device and the events.
func (s *Service) RequireToken(subjectFor SubjectFunc) func(http.Handler) http.Handler {
	if subjectFor == nil {
		panic("token: RequireToken was given a nil SubjectFunc. The workspace in a token is a candidate, and revalidating it is the application's")
	}
	guard := middleware.RequireToken(carried{subjectFor: subjectFor})

	return func(next http.Handler) http.Handler {
		guarded := guard(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := WithClientIP(r.Context(), RemoteIP(r))
			// A token with the wrong prefix is not looked up: it cannot be one of
			// ours, and the store is not asked to prove it.
			if token := bearerToken(r); strings.HasPrefix(token, s.cfg.AccessPrefix) {
				digest := DigestOf(token)
				p, ok, err := s.Resolve(ctx, digest)
				if err != nil {
					panic(err)
				}
				if ok {
					ctx = context.WithValue(ctx, authenticatedKey, authenticated{principal: p, digest: digest})
				}
			}
			guarded.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// bearerToken is the token of an Authorization: Bearer header, or empty. The
// scheme is compared without regard to case, as RFC 9110 says, and the value is
// trimmed.
func bearerToken(r *http.Request) string {
	const scheme = "bearer "
	v := r.Header.Get("Authorization")
	if len(v) < len(scheme) || !strings.EqualFold(v[:len(scheme)], scheme) {
		return ""
	}
	return strings.TrimSpace(v[len(scheme):])
}
