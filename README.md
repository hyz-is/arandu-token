<p align="center">
  <img src=".github/logo.svg" alt="Arandu" width="180">
</p>

# Arandu Token

Authentication of native apps for an Arandu application: a token per person and
per device, with renewal and revocation.

A device signs in with whatever the application asks of it, and the application
calls `Issue`. The device gets two opaque tokens: a short-lived **access** token
it sends as `Authorization: Bearer` on every request, and a long-lived
**refresh** token it exchanges for the next pair. A refresh token is good once.
Presenting one that was already exchanged is taken for theft and revokes that
device's whole session.

The store keeps the SHA-256 digest of each token and never the token. A token is
shown once, in the `Pair` that issues it, and no log line, error, `String()`,
`slog` value or JSON of this package carries one.

## What it is not

It does not know users. It stores an identifier, never checks a password or a
second factor, and registers no route: the sign-in, the refresh and the sign-out
of a native app are the application's own endpoints, because they check the
application's passwords and answer in the application's shape.

It never decides the tenant of data. The workspace kept beside a token is a
**candidate**. The application revalidates the Membership on every request, with
`WorkspaceService.SubjectFor` or whatever it calls it, and only then issues the
Grant. The tenant of data comes from `data.Tenant(g)` and from nowhere else.

## Install

```bash
go get github.com/hyz-is/arandu-token
```

## Wire it

An Arandu application registers a module explicitly. There is no service
provider, no container and no discovery, so these are the lines to paste into
`bootstrap/app.go` and there are no others.

The import, with the other module imports:

```go
import (
	token "github.com/hyz-is/arandu-token"
)
```

The construction, in `Build`, after the database handle exists and before
`k.Register`. The prefixes are the application's own: a credential found in a log
or a repository then says whose it is, and a secret scanner can match it.

```go
	tokenModule, err := token.New(token.Config{
		AccessPrefix:  "alpra_",
		RefreshPrefix: "alprr_",
		AccessTTL:     15 * time.Minute,    // the default
		RefreshTTL:    60 * 24 * time.Hour, // the default
		Events:        auditTokens(activity),
	}, db)
	if err != nil {
		return App{}, err
	}
```

And the registration, inside the `k.Register(...)` calls already there:

```go
	k.Register(tokenModule)
```

Then, once, before the application serves:

```bash
aru migrate
```

The module owns two tables, `token_credentials` and `token_devices`, which is why
the migration step is not optional and why `arandu.mod.toml` says
`migrations = true`. It registers a daily task that deletes what expired, so
`Config.CleanSpec` moves it and `token.CleanDisabled` turns it off for an
application that calls `Service.Clean` itself.

## The API

All of it is on `tokenModule.Service()`.

| call | what it does |
| --- | --- |
| `Issue(ctx, userID, workspaceID, device) (Pair, error)` | Signs a device in. A device has one session: signing in again on it ends the previous one. `workspaceID` may be empty for a session bound to none yet. |
| `Refresh(ctx, refresh) (Pair, error)` | Exchanges a refresh token for a new pair and the old one stops working. A refresh token already exchanged is a reuse: the whole session is revoked, `EventReuseDetected` is recorded, and the answer is `ErrReuseDetected`. |
| `Resolve(ctx, digest) (Principal, bool, error)` | Who a valid access token was issued to. `ok` is false for a token that was never issued, expired, was revoked or is a refresh token. The error is for the store failing, which is not a 401. |
| `Switch(ctx, access, workspaceID) (Pair, error)` | Moves the session to another workspace: the old pair is revoked and a new one is issued. The application checks the Membership first. |
| `Revoke(ctx, token) error` | A device signing out, with its access or its refresh token. Idempotent. |
| `RevokeDevice(ctx, userID, deviceID) error` | The user removing one of their devices. `ErrNotFound` for a device that is not theirs. |
| `RevokeAllForUser(ctx, userID) (int, error)` | Every session of the user: a password change, a suspension, "sign out everywhere". |
| `ListDevices(ctx, userID) ([]Device, error)` | Devices with a live session: name, platform, last use and last address. |
| `Clean(ctx) (Cleaned, error)` | Deletes expired and revoked credentials older than `Config.Retention`. |
| `RequireToken(subjectFor)` | Middleware for `Authorization: Bearer`. |
| `Resolver(subjectFor)` | The framework's `middleware.TokenResolver`, for an application that mounts `middleware.RequireToken` itself. |

`Device` is `{ID, Name, Platform}`: the install the native app signs in from.
`ID` is generated once by the app and sent on every sign-in; it is scoped to the
user, so the same value on two accounts is two devices.

### Signing in

The application checks the password and the second factor, then issues:

```go
func (c *Auth) Login(ctx *fhttp.Context) error {
	reqCtx := token.WithClientIP(ctx.Ctx(), token.RemoteIP(ctx.Request))

	err := token.Guard(reqCtx, c.throttle, "app", email, token.RemoteIP(ctx.Request),
		func(context.Context) (bool, error) { return c.users.Verify(reqCtx, email, password, code) })
	if err != nil {
		return err // ErrBadCredentials is 401, a LockedError is 429 with Retry-After
	}

	user, workspace, err := c.workspaces.Default(reqCtx, email) // the Membership the user starts in
	if err != nil {
		return err
	}
	pair, err := c.tokens.Issue(reqCtx, user.ID, workspace.ID, token.Device{
		ID: ctx.Input("device_id"), Name: ctx.Input("device_name"), Platform: ctx.Input("platform"),
	})
	if err != nil {
		return err
	}
	return ctx.JSON(http.StatusCreated, pair.Reveal())
}
```

`pair.Reveal()` is the one place the tokens leave the package: marshalling it
writes `token_type`, `access_token`, `refresh_token`, `expires_in`,
`access_expires_at`, `refresh_expires_at`, `workspace_id` and `device_id`.
Formatting or logging a `Pair`, or the `Revealed` it returns, prints
`[redacted]`; marshalling a `Pair` writes `"[redacted]"` for each token.

### Authenticating requests

`SubjectFunc` is where the application revalidates the Membership. The workspace
in the principal is a candidate; the function answers the Subject scoped to the
workspace it found, with the roles and actions the permission module gives it
there, or `token.ErrUnknownToken` when the user no longer belongs:

```go
	subjectFor := func(ctx context.Context, p token.Principal) (security.Subject, error) {
		subject, err := workspaces.SubjectFor(ctx, p.UserID, p.WorkspaceID)
		if errors.Is(err, workspace.ErrNotAMember) {
			return security.Subject{}, token.ErrUnknownToken // a 401, as for a token nobody issued
		}
		return subject, err // any other error is a 500, not a 401
	}

	api := r.Group("/api", tokenModule.Service().RequireToken(subjectFor))
```

Behind it a handler reads who is asking with `ctx.User()` exactly as it does
behind `RequireAuth`, and `token.PrincipalFrom(ctx.Ctx())` adds the device. The
Grant comes from `security.Authorize` on that Subject, as on any request.

A request with no token, a token nobody issued, one that expired or was revoked,
or whose `SubjectFunc` says `ErrUnknownToken`, is answered the same 401 with
`WWW-Authenticate: Bearer`. The token is read from the header and from nowhere
else. The address of the request comes from `RemoteAddr` and never from a header
the client writes, so behind a proxy the application's trusted-proxy middleware
has to have rewritten it.

An application that prefers the framework's own middleware uses
`middleware.RequireToken(tokenModule.Service().Resolver(subjectFor))`; it gets the
same answers, without the device on the context.

### Renewing

```go
func (c *Auth) Refresh(ctx *fhttp.Context) error {
	reqCtx := token.WithClientIP(ctx.Ctx(), token.RemoteIP(ctx.Request))
	pair, err := c.tokens.Refresh(reqCtx, ctx.Input("refresh_token"))
	if err != nil {
		return err // ErrInvalidToken and ErrReuseDetected are both 401
	}
	return ctx.JSON(http.StatusOK, pair.Reveal())
}
```

A client that refreshes from two requests at once sends the same token twice,
and with the default configuration the second is a reuse and signs the device
out. Serialise the refresh in the client, or set `Config.ReuseGrace` to a few
seconds: a reuse inside it is refused as `ErrInvalidToken` and revokes nothing.
The price is those seconds of exposure.

### Switching workspace

```go
	pair, err := c.tokens.Switch(reqCtx, bearer, workspaceID)
```

The application first checks that the user belongs to `workspaceID`. The new pair
replaces the old one, refresh token included.

### Protecting the sign-in

A native app has no Turnstile. `token.Guard` runs the check of credentials behind
any `SignInThrottle`, the interface of the framework's `auth.MemoryThrottle`:

```go
	throttle, err := token.NewLimiter(token.LimiterPolicy{}) // or auth.NewMemoryThrottle()
```

`Limiter` counts two budgets in one indivisible step, the **account** across all
addresses (5 by default) and the **address** across all accounts (25), and the
attempt that spends one locks the key: 30 seconds the first time, doubling each
time it locks again within a day, up to an hour. A refused attempt costs nothing,
so hammering a locked account does not extend it. A good sign-in forgets the
account and gives the address one unit back. The table is bounded and it starts
no goroutine.

It lives in the memory of one process. Behind several instances the budgets
multiply by the number of instances, and an application that runs more than one
gives `Guard` a throttle backed by a shared store.

### Recording what happened

`Config.Events` receives `token.issued`, `token.refreshed`, `token.reuse_detected`,
`token.revoked` and `token.switched`, with the user, workspace, device, session,
reason, address and time, and never a token or a digest. It runs **inside the
transaction of the act**, so a recorder that writes with the application's
database handle joins it, and an error from the recorder fails the act. Writing
them to `arandu-activitylog`:

```go
func auditTokens(logger *activitylog.Logger) token.Recorder {
	return token.RecorderFunc(func(ctx context.Context, e token.Event) error {
		//arandu:system-grant the event is about a session of this workspace; the entry is written under it.
		g := security.SystemGrant("token.audit", e.WorkspaceID)
		_, err := logger.Activity(ctx, g).
			OnRef(activitylog.Ref{Type: "user", ID: e.UserID}).
			Event(string(e.Kind)).
			WithProperties(map[string]any{"device_id": e.DeviceID, "reason": e.Reason, "ip": e.IP}).
			Log(string(e.Kind))
		return err
	})
}
```

A session with no workspace yet has no tenant for a Grant, so the application
decides where those entries go.

## Configuration

| field | default | meaning |
| --- | --- | --- |
| `AccessPrefix` | `tka_` | readable start of an access token. |
| `RefreshPrefix` | `tkr_` | readable start of a refresh token. It differs from the other, and neither starts the other. |
| `AccessTTL` | 15 minutes | at most 24 hours. |
| `RefreshTTL` | 60 days | counted from the token that rotated into it; at least `AccessTTL`, at most 400 days. |
| `Retention` | 7 days | how long expired and revoked credentials stay. It is also how long an exchanged refresh token is recognised as a reuse. |
| `ReuseGrace` | 0 | seconds after an exchange in which the old token is refused without revoking the session. At most 2 minutes. |
| `TouchInterval` | 1 minute | least time between two writes of a token's last use and its device's last address. Negative writes on every request. |
| `CleanSpec` | `17 3 * * *` | cron of the scheduled clean; `token.CleanDisabled` for none. |
| `Events` | nil | the `Recorder`. |
| `Clock` | `time.Now` | for tests. |

The zero `Config{}` is a valid configuration. `New` returns an error rather than
starting half-wired.

## Tables

| table | holds |
| --- | --- |
| `token_credentials` | `digest` (unique), `kind` (`access` or `refresh`), `family_id`, `user_id`, `workspace_id`, `device_id`, `expires_at`, `last_used_at`, `revoked_at`, `revoked_reason`, `created_at`. One row per token; a sign-in's pairs share a `family_id`. |
| `token_devices` | `user_id` + `device_id` (unique), `name`, `platform`, `last_ip`, `last_used_at`, `created_at`, `updated_at`. |

They carry the package's name so that they sit beside a `devices` or `tokens`
table the application already has.

## Layout

```
module.go    registration, schedule, health and migrations
config.go    what the application passes in
service.go   issue, refresh, resolve, switch, revoke, list and clean
http.go      the Bearer middleware and the context helpers
limiter.go   the throttle for sign-in, with a progressive lockout
secret.go    Secret, Pair and Revealed: tokens that do not print
events.go    what the application records
errors.go    the errors, each with the status the router answers it
model.go     Device, Principal, Digest and the validation of identifiers
actions.go   the one action the schedule runs under
```

## Why the service reads its tables without a Grant

Every other module reaches its rows through a Grant, because a row belongs to a
tenant and the Grant names it. A credential cannot work that way: the question
`Resolve` answers is who is asking, which comes before any Grant exists, and the
only thing the caller holds is the token. hesape's session store reads its table
the same way, keyed by the secret and by nothing else. Nothing here decides a
tenant of data; the Grant that does is issued by the application afterwards.

## Tests

```bash
export GOWORK=off
go test -race ./...
```

The feature tests run on SQLite, and also on PostgreSQL when
`ARANDU_TEST_POSTGRES_DSN` names a server; each test gets a schema of its own.

```bash
ARANDU_TEST_POSTGRES_DSN='postgres://user@localhost:5432/arandu_token_test?sslmode=disable' go test -race ./...
```

## Licence

MIT. See [LICENSE.md](LICENSE.md). Copyright HYZIS.
