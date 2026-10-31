# Contributing

Thank you for considering a contribution.

## Before you open a pull request

Run the four gates. They are what CI runs, and a pull request that fails one of
them fails for everybody who pulls after it.

```bash
gofmt -l $(find . -name '*.go' -not -path '*/testdata/*' -not -name '*.kyse.go')
go build ./...
go vet ./...
go test -race ./...
```

The two filters on `gofmt` are not preference. `gofmt` is the only tool in the
chain that ignores build tags, so it reads files the compiler deliberately
excludes; `testdata/` holds fixtures that are invalid on purpose.

The feature tests also run on PostgreSQL when `ARANDU_TEST_POSTGRES_DSN` names a
server, and a change that touches a statement or the schema is not finished until
they pass there as well.

## What a change has to keep true

Six properties are the reason this package is what it is. A change that breaks
one of them will not be merged, whatever else it improves. AGENTS.md lists them
with the test that holds each.

1. **Only the digest is stored.** A token is shown once, in the `Pair` that issues
   it. It is not in a table, an error, a log line, `String()`, `LogValue` or a
   JSON that is not the body `Pair.Reveal` builds.
2. **A refresh token is good once.** Reusing an exchanged one revokes that
   device's session, and of two simultaneous exchanges exactly one wins.
3. **A user reaches nothing of another's.** Every call that acts on devices
   takes the user it acts on and filters by it.
4. **The workspace is a candidate.** The module never decides a tenant of data.
5. **The credentials table is cleaned.** A table that only grows is a defect.
6. **`arandu.mod.toml` matches the code.** Adding an outbound call, a file write
   or a process means declaring it there in the same commit.

A statement is written in `service.go` and nowhere else. It takes digests, never
tokens, and every instant it writes is UTC to the microsecond. A change to the
schema is a new migration with a new name; a published migration is never
edited.

Do not add a route, a user, a password check or a log line. They are the
application's, and the tests that refuse them say why.

## Style

Everything in the source is in English: identifiers, doc comments, internal
comments, error messages, log messages, and the names and messages of tests.
`pkg.go.dev` publishes the doc comments, and its readers are users of this
package.

Every exported symbol carries a doc comment saying what it does. The comment
documents the symbol and nothing else: no dates, no issue numbers, no
references to other repositories. Why a signature is what it is belongs there
when it is a fact about the code; anything else belongs in the pull request.

## Commits

One commit per logical change. Formatting is not mixed with behaviour, because
a diff that does both is a diff nobody reviews.

## Reporting a vulnerability

Do not open an issue. See [SECURITY.md](SECURITY.md).

## Licence

By contributing you agree that your contribution is licensed under the MIT
licence, the same as the rest of github.com/hyz-is/arandu-token.
