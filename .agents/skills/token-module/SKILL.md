---
name: token-module
description: Change what this Arandu package does — its service calls, configuration, schema, events, middleware or throttle. Use when the request is to "add a method to the service", "add a config option", "change the token format", "add a column", "write a migration", "add an event", "change how the middleware answers", "change the lockout", "add a field to Device", "make it run something on a schedule", or when a change touches module.go, config.go, service.go, http.go, limiter.go, events.go or model.go. Covers foundation.Module and the optional interfaces this package opts into, why every statement lives in service.go, atomic statements and transactions, the migration name that carries the order, and how a new credential-handling line stays inside the tests that hold it.
license: MIT
---

# The module contract

`foundation.Module` is `Name()` and `Routes()`. This module registers no route:
`Routes` is empty on purpose, and it opts into `Migratable` (its tables),
`Schedulable` (the clean) and `Health` (the storage). Anything else it needs is
declared the same way, by implementing the interface, and registered by hand in
the installer's `bootstrap/app.go`.

## Where things go

- **A statement** is written in `service.go` and nowhere else, through `s.exec`,
  `s.db.QueryContext` or `s.db.QueryRowContext`, with `?` placeholders (the
  handle rebinds them for PostgreSQL) and every value as an argument. The
  condition fragments `endSessions` takes are fixed text in that file.
- **A multi-statement act** runs inside `data.Transaction`, with the recorder
  called inside it, so an event the log refuses rolls the act back.
- **A race** is settled by one conditional `UPDATE ... WHERE revoked_at IS NULL`
  and its row count, never by a `SELECT` followed by a write. That is what makes
  one of two simultaneous refreshes win.
- **An instant** is `s.now()`: UTC, to the microsecond, from `Config.Clock`.
- **A config field** is validated in `Config.Validate` and defaulted in
  `withDefaults`, which runs after it and never before.
- **A migration** is a new type with a new name that sorts after the others
  (`YYYYMMDD_NNNN_what_it_does`), with an `Up` and a `Down`. A published
  migration is never edited. Name it in `CHANGELOG.md` and `UPGRADE.md`.
- **An event** is a new `EventKind`, recorded in the same transaction. It names
  people, devices and workspaces, never a token or a digest.

## What stays true

The tests that hold the properties read this code: `tests/Unit/audit_test.go`
refuses a log or print line, a statement argument named for a token, a second
call of `Reveal`, a package variable that holds state, and an address read from a
header. If a change needs one of those, it is the change that is wrong, or the
test needs a reason written next to it in the same commit.

`Resolve` returns an error for the store failing and `ok = false` for a token
that is not good. Do not merge them: the first is a 500 and the second a 401.

After any change, `go test -race ./...` with `ARANDU_TEST_POSTGRES_DSN` set: the
statements are shared by SQLite and PostgreSQL, and a time comparison or an
upsert that works on one is the usual way to break the other.
