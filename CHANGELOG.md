# Changelog

Everything worth knowing about a release of Arandu Token is recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

A published module version is immutable: Go serves it from the proxy forever, so
a release is corrected by another release and never by moving a tag.

## [Unreleased]

## [0.1.0] - 2026-10-31

The first release: authentication of native apps with a token per person and per
device, with renewal and revocation.

### Added

- `Service.Issue`: signs a device in with a `Pair` of an access token (15 minutes
  by default) and a refresh token (60 days by default), both opaque random
  strings with a readable prefix the application chooses. Only the SHA-256 digest
  of each is stored. A device has one session: signing in again on it ends the
  previous one.
- `Service.Refresh`: exchanges a refresh token for a new pair and the old one
  stops working. Presenting a refresh token that was already exchanged is taken
  for theft: the whole session of that device is revoked, `EventReuseDetected` is
  recorded, and the answer is `ErrReuseDetected`. Of two simultaneous exchanges
  exactly one wins. `Config.ReuseGrace` lets an application that refreshes from
  parallel requests refuse the loser without revoking the session.
- `Service.Resolve`, answering a `Principal` (user, workspace candidate, device
  and session) for a `Digest`, and `Service.Resolver`, the framework's
  `middleware.TokenResolver` over it. The workspace is a candidate that the
  application revalidates through a `SubjectFunc` on every request.
- `Service.RequireToken`: middleware for `Authorization: Bearer` that puts the
  application's Subject and the `Principal`, with its device, on the context. It
  answers every refusal the same 401. `PrincipalFrom`, `WithClientIP`,
  `ClientIPFrom` and `RemoteIP` are its helpers.
- `Service.Switch`: moves a session to another workspace with a new pair, and
  revokes the old one.
- `Service.Revoke` (a device signing out), `Service.RevokeDevice` (a user
  removing one of theirs), `Service.RevokeAllForUser` and `Service.ListDevices`
  (name, platform, last use and last address).
- `Service.Clean` and the scheduled task `token.credentials.clean`, run by the
  action `TokenClean`, which deletes expired and revoked credentials older than
  `Config.Retention` (7 days by default). `Config.CleanSpec` moves it and
  `CleanDisabled` turns the schedule off.
- `Secret`, `Pair` and `Revealed`: a token prints, logs and marshals as
  `[redacted]` in every verb and encoding, and `Pair.Reveal` is the one door that
  builds the body that hands the tokens over.
- `Event` and `Recorder`, with `EventIssued`, `EventRefreshed`,
  `EventReuseDetected`, `EventRevoked` and `EventSwitched`. The recorder runs
  inside the transaction of the act and an error from it fails the act.
- `Limiter`, a `SignInThrottle` with an account budget across addresses, an
  address budget across accounts and a progressive lockout, and `Guard`, which
  runs a check of credentials behind it or behind the framework's own
  `auth.MemoryThrottle`. `LockedError` is a 429 with `Retry-After`.
- The migration `20261031_0001_create_token_tables`, which creates
  `token_credentials` and `token_devices`. Run `aru migrate`.
- Errors that carry the status the router answers them with: `ErrInvalidToken`,
  `ErrReuseDetected` and `ErrBadCredentials` are 401, `ErrNotFound` is 404.

