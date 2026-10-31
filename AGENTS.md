# Working on Arandu Token

This is an Arandu package for the authentication of native apps: a token per
person and per device, with renewal and revocation. A service that owns the
database handle, a Bearer middleware, a sign-in throttle and the two tables
behind them. It registers no route of its own.
It is a Go module somebody `go get`s and registers by hand in their own
`bootstrap/app.go`, which is the whole difference from working in an
application. There is no service provider, no container and no discovery — if a
line of wiring is not written in the installer's repository, it does not happen.

Read `.agents/skills/` before writing code. Each skill is a procedure, and the
one you need is named by the situation you are in.

## The gates

Nothing is finished until all four exit zero.

```sh
export GOWORK=off
gofmt -l $(find . -name '*.go' -not -path '*/testdata/*' -not -name '*.kyse.go')
go build ./...
go vet ./...
go test -race ./...
```

`GOWORK=off` is not borrowed from somewhere else, and here it is not a
preference either. This checkout may sit beside a Go workspace that lists the
framework repositories and does not list this one; when it does, every command
above fails before it compiles anything:

```
pattern ./...: directory prefix . does not contain modules listed in go.work
or their selected dependencies
```

With the workspace off, the module resolves the framework version in `go.mod` —
which is what CI compiles against, and what somebody's `go get` will get.

Both filters on `gofmt` are load-bearing in the toolchain even where this
repository has nothing for them to skip: `gofmt` is the only tool in the chain
that ignores build tags, and `testdata/` is where a fixture is allowed to be
invalid on purpose.

`aru doctor` is not one of the gates, and running it here costs a minute and
answers nothing:

```
this is not an Arandu project: no go.mod, main.go and arandu.toml together.
Run it from inside a project, or create one with `aru new`
```

It exits 1. It reads applications, and this is a library.

It does not read this one after it is installed either, and that is why
`tests/Unit/audit_test.go` exists. The doctor walks the application's own tree,
skips `vendor/`, and opens the one `arandu.mod.toml` at its root; it never loads
a dependency. So `tenant-from-request`, `system-grant-without-tenant` and
`permission-not-declared` never see a line of an installed package, and whatever
this one must prove about itself it proves in its own suite or nowhere.

## What this repository holds

| | measured with |
| --- | --- |
| 10 Go files, one per role, all in one package at the root | `grep -l '^package token' *.go` |
| 11 test files in two categories | `find tests -name '*_test.go'` |
| 2 tables, 1 migration | `grep -c 'Schema().Create' module.go` |
| 1 action, run by the scheduler and offered to nobody | `grep -cE '^\t[A-Za-z]+ +security.Action = ' actions.go` |
| 2 direct dependencies, both under `arandu-io` (and two connectors the tests run on) | `go list -m -f '{{if and (not .Indirect) (not .Main)}}{{.Path}} {{.Version}}{{end}}' all` |

The layout is by role rather than by layer, so the package reads top to bottom:

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

The `Service` is the only owner of the database handle and the only place a
statement is written. It reads and writes its tables **without a Grant**, and
that is not an oversight: the question `Resolve` answers is who is asking, which
comes before any Grant exists, and the only thing the caller holds is the token.
hesape's session store reads its table the same way, keyed by the secret alone.
The workspace stored beside a token is a candidate; the application revalidates
the Membership on every request and issues the Grant. Nothing in this package
decides the tenant of data.

## What does not exist here

Reaching for one of these is the most common way to write a change that is
rejected in review. None of them is missing by accident.

| A change reaches for | What is here instead |
| --- | --- |
| a service provider, a container, a `Register()` that discovers things | `New(cfg, db)`, called by hand in the installer's `bootstrap/app.go` |
| a global `DB`, an `init()`, a package variable that holds state | the `*data.DB` handed to `New`. `TestThePackageIsComposedByHand` refuses a package variable that is not an error or a pattern |
| a route, a controller, a screen | nothing. Sign-in, refresh and sign-out check the application's passwords and answer in the application's shape, so they are the application's endpoints |
| a user table, a password check, a second factor | an identifier. The module does not know a user beyond a string |
| a policy, a role, an ACL of its own | the application's, through arandu-permission. The one action here belongs to the scheduler |
| a tenant read from a token, a header, a path or a body | `Principal.WorkspaceID` is a candidate and `SubjectFunc` revalidates it. The Grant carries the tenant |
| a log line, a `fmt.Print`, a token in an error | an `Event` the application records. `TestNothingInThePackageLogsPrintsOrReadsAHeaderOfTheClient` refuses the lines |
| a token stored, compared or passed to a statement | its SHA-256 digest. `TestNoStatementIsHandedAToken` refuses a statement argument named for one |
| a second place where a `Secret` becomes a string | `Reveal`, called only in `secret.go` (`TestAnAccessTokenLeavesThroughOneDoor`) |
| an address read from `X-Forwarded-For` | `RemoteAddr`, rewritten by the application's trusted-proxy middleware |
| a third dependency | an argument, first. This module is imported into other people's builds |

## The properties

These are the reason the package is shaped the way it is. A change that breaks
one of them is not merged, whatever else it improves. The feature tests drive
them through a real database, on SQLite and on PostgreSQL.

1. **Only the digest is stored.** `TestNoTokenIsEverStoredLoggedPrintedOrEncoded`
   runs a whole life of tokens, then looks for every token, and the random part
   of every token, in the tables, in every error, in `fmt` under every verb, in
   `slog` and `log`, and in JSON. Only `Pair.Reveal` writes a token, on purpose.
2. **A refresh token is good once.** Exchanging it rotates the pair; presenting
   one that was exchanged revokes the whole session of that device and no other
   (`ErrReuseDetected`). Of two simultaneous exchanges exactly one wins, because
   the exchange is one conditional `UPDATE` and not a read and a write.
3. **A user reaches nothing of another.** Devices are scoped by user: the same
   device ID on two accounts is two devices, and revoking by device of somebody
   else is `ErrNotFound`.
4. **The workspace is a candidate.** `RequireToken` hands the principal to the
   application's `SubjectFunc` on every request, and a Subject that is not the
   token's user is a wiring mistake that panics, not a request that proceeds.
5. **The credentials table does not grow without bound.** The module schedules the
   clean, and `Retention` is what a reuse can still be recognised for.
6. **`arandu.mod.toml` matches the code.** Adding an outbound call, a file write
   or a process means declaring it there in the same commit.

What the audit does not reach is written at the top of the file it lives in. It
reads syntax, so dynamic dispatch, reflection, and wrappers around the named
seams are invisible to it. A green run means no such thing was found written
down, not that none exists.

## Running against PostgreSQL

The feature tests run on SQLite always. With a server they run a second time on
PostgreSQL, each test in a schema of its own that is dropped afterwards:

```sh
export ARANDU_TEST_POSTGRES_DSN='postgres://paulorlima9@localhost:5432/arandu_token_test?sslmode=disable'
go test -race -count=1 ./tests/Feature/
```

A change is not finished until the suite also passes there.

## Writing code

Everything in the source is in English: identifiers, doc comments, internal
comments, error messages, log messages, and the names and messages of tests.
`pkg.go.dev` publishes the doc comments and its readers are users of this
package.

Every exported symbol carries a doc comment, and the comment documents the
symbol and nothing else. Why a signature is what it is belongs there when it is
a fact about the code — *"the value is held because Go does not build a type
from a string"* stays. A date, an issue number, a version in progress or the
name of another repository does not.

Tests go under `tests/`, in a capitalized category directory declaring a
lowercase external package: `tests/Unit` holds `package unit_test`,
`tests/Feature` holds `package feature_test`. Both import the package by its
module path, which is what makes them see exactly what a caller sees. A test
that genuinely needs something unexported goes beside the code as
`*_internal_test.go`, and the suffix is how it says so.
