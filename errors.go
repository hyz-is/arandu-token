package token

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// statusError is an error that knows the status the router answers it with.
//
// The router asks any error for HTTPStatus, so a handler that returns one of
// these answers 401 or 404 without choosing the status itself. None of them
// carries a token, a digest or an identifier: what the error says is what the
// client is allowed to know.
type statusError struct {
	message string
	status  int
}

func (e *statusError) Error() string   { return e.message }
func (e *statusError) HTTPStatus() int { return e.status }

// ErrInvalidToken is what every credential that cannot be used is answered
// with: one that was never issued, one that expired, one that was revoked, one
// of the other kind. It is one error for all of them on purpose, because a
// caller told which of them it was learns what exists.
//
// The router answers it with 401.
var ErrInvalidToken error = &statusError{"token: the token is not valid", http.StatusUnauthorized}

// ErrReuseDetected is what Refresh answers when the refresh token it was given
// had already been exchanged. The family of that device has been revoked by the
// time this is returned: whoever holds any of its tokens, the owner or a thief,
// has to sign in again.
//
// It is a distinct error so that the application can tell the owner. The client
// is still answered with 401.
var ErrReuseDetected error = &statusError{"token: the refresh token was already used and the session was revoked", http.StatusUnauthorized}

// ErrNotFound is what RevokeDevice answers when the user has no live session on
// that device. A device of another user is not found either: the two cases are
// indistinguishable.
//
// The router answers it with 404.
var ErrNotFound error = &statusError{"token: device not found", http.StatusNotFound}

// ErrBadCredentials is what Guard answers when the check it ran said the
// credentials were wrong. The router answers it with 401.
var ErrBadCredentials error = &statusError{"token: the credentials are not valid", http.StatusUnauthorized}

// ErrTooManyAttempts is the error a LockedError matches with errors.Is.
var ErrTooManyAttempts = errors.New("token: too many attempts")

// LockedError is what Guard answers when the throttle refuses an attempt. It
// matches ErrTooManyAttempts with errors.Is, the router answers it with 429 and
// a Retry-After header, and it carries how long to wait.
type LockedError struct {
	// RetryAfter is how long until the throttle takes another attempt.
	RetryAfter time.Duration
}

// Error says that the account is locked and for how long, in whole seconds.
func (e *LockedError) Error() string {
	return fmt.Sprintf("token: too many attempts, try again in %d seconds", e.seconds())
}

// Is matches ErrTooManyAttempts.
func (e *LockedError) Is(target error) bool { return target == ErrTooManyAttempts }

// HTTPStatus is 429.
func (e *LockedError) HTTPStatus() int { return http.StatusTooManyRequests }

// GetHeaders is the Retry-After header the router sends.
func (e *LockedError) GetHeaders() http.Header {
	return http.Header{"Retry-After": []string{strconv.Itoa(e.seconds())}}
}

// seconds is RetryAfter rounded up to whole seconds, and at least one.
func (e *LockedError) seconds() int {
	s := int((e.RetryAfter + time.Second - 1) / time.Second)
	if s < 1 {
		s = 1
	}
	return s
}
