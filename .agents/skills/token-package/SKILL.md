---
name: token-package
description: Install, wire and use the Arandu Token package (Go, Arandu) in an application, to authenticate a native app with a token per person and per device. Use when the request is to "install Arandu Token", "add token auth to the app", "go get github.com/hyz-is/arandu-token", "wire it into bootstrap/app.go", "register the module", "sign in a native app", "issue a token", "refresh token", "sign out a device", "list the user's devices", "switch workspace in the app", "protect the app login from guessing", "Authorization Bearer", "the table does not exist", or when a project's go.mod already requires github.com/hyz-is/arandu-token. Covers the wiring and where it goes, the Config fields, the calls and what the application still owns, revalidating the Membership on every request, and the migration step that is not optional.
license: MIT
metadata:
  audience: app
---

# Using Arandu Token

Authentication of native apps: an access token and a refresh token per person and
per device, with rotation and revocation. It is registered by hand: there is no
service provider, no container and no discovery, so if a line is not written in
the application, it does not happen.

It registers **no route**. The sign-in, the refresh and the sign-out are the
application's own endpoints, because they check the application's passwords and
answer in the application's shape. The module issues, exchanges, resolves and
revokes; it does not know users and never decides the tenant of data.

## Install

```bash
go get github.com/hyz-is/arandu-token
```

## The wiring, and where it goes

All of it is in `bootstrap/app.go`. `aru make:module` does not edit this file.

```go
import token "github.com/hyz-is/arandu-token"

	tokenModule, err := token.New(token.Config{
		AccessPrefix:  "myapp_a_", // readable, and the application's own
		RefreshPrefix: "myapp_r_",
		Events:        auditTokens(activity), // optional: a token.Recorder
	}, db)
	if err != nil {
		return App{}, err
	}
	k.Register(tokenModule)
```

Then once, before the application serves:

```bash
aru migrate
```

The module owns `token_credentials` and `token_devices`, and schedules a daily
clean of what expired. If the tables are not there, `Health` says so and points
at `aru migrate`.

## The calls, all on `tokenModule.Service()`

- `Issue(ctx, userID, workspaceID, token.Device{ID, Name, Platform})` after the
  application verified the password and the second factor, and that the user
  belongs to the workspace. `Pair.Reveal()` is the body to send.
- `Refresh(ctx, refresh)`; `ErrInvalidToken` and `ErrReuseDetected` are 401. A
  reuse has already revoked the device's session.
- `Switch(ctx, access, workspaceID)` after the application checked the
  Membership.
- `Revoke(ctx, token)` for a sign-out, `RevokeDevice(ctx, userID, deviceID)` for a
  user removing a device, `RevokeAllForUser(ctx, userID)` after a password
  change or a suspension.
- `ListDevices(ctx, userID)`. The application decides who may ask about whose
  devices; the module acts on the user it is given.
- `token.Guard(ctx, throttle, scope, identity, client, check)` around the check
  of credentials, with `token.NewLimiter(token.LimiterPolicy{})` or the
  framework's `auth.NewMemoryThrottle()`.

Put the request's address on the context with
`token.WithClientIP(ctx, token.RemoteIP(r))` before `Issue`, `Refresh`, `Switch`
and the revocations; `RequireToken` does it itself.

## Authenticating requests

```go
	subjectFor := func(ctx context.Context, p token.Principal) (security.Subject, error) {
		subject, err := workspaces.SubjectFor(ctx, p.UserID, p.WorkspaceID) // revalidates the Membership
		if errors.Is(err, workspace.ErrNotAMember) {
			return security.Subject{}, token.ErrUnknownToken // 401
		}
		return subject, err
	}
	api := r.Group("/api", tokenModule.Service().RequireToken(subjectFor))
```

The workspace in the principal is a **candidate**. Revalidate it on every request;
the Grant comes from `security.Authorize` on the Subject, and the tenant of data
from `data.Tenant(g)`. Never use `p.WorkspaceID` as a tenant.

## Do not

- Do not `Println`, log or marshal a `Pair`, a `Secret` or an error with a token
  in it. They print `[redacted]`; `Pair.Reveal()` is the only door.
- Do not store the token, or compare it: store nothing, or its digest
  (`token.DigestOf`).
- Do not read the address from `X-Forwarded-For`; use `token.RemoteIP` behind the
  trusted-proxy middleware.
- Do not call `Refresh` from several requests at once in the client. With the
  default configuration the second one signs the device out; serialise it, or set
  `Config.ReuseGrace`.
- Do not use the `Limiter` behind several instances and expect one budget; give
  `Guard` a shared-store throttle there.
