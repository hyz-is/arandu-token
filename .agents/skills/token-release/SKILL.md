---
name: token-release
description: Get this Arandu package green, declared and published. Use when the request is to "run the gates", "check it builds", "the tests fail", "go build says the directory prefix does not contain modules listed in go.work", "aru doctor says this is not an Arandu project", "update arandu.mod.toml", "add a dependency", "bump the framework", "tag a release", "publish it", "go get cannot find the module", "write the changelog", or before opening a pull request. Covers the four gates and why each filter is there, what the manifest declares and who checks it, the immutability of a published module version, and what breaks somebody else's build.
license: MIT
---

# Getting it green and out

## The four gates

Nothing is finished until all four exit zero.

```sh
export GOWORK=off
gofmt -l $(find . -name '*.go' -not -path '*/testdata/*' -not -name '*.kyse.go')
go build ./...
go vet ./...
go test -race ./...
```

`GOWORK=off` first, and here it is not a habit. This checkout may sit beside a
Go workspace that lists the framework repositories and does not list this one.
When it does, `go build ./...` exits 1 before compiling anything:

```
pattern ./...: directory prefix . does not contain modules listed in go.work
or their selected dependencies
```

That is the workspace refusing to answer for a module it was not told about, and
it says nothing about the code. With the workspace off, the module resolves the
versions in `go.mod` — which is what CI compiles against, and what somebody's
`go get` will get. A pass obtained with a workspace active is a pass against
whatever happens to be checked out beside you.

`aru doctor` is not a gate. It exits 1 here with *"this is not an Arandu
project: no go.mod, main.go and arandu.toml together"* — it reads applications,
and this is a library.

This package has no generated model: its statements are written in `service.go`,
so there is no `aru model:build` step. The feature tests also run on PostgreSQL
when `ARANDU_TEST_POSTGRES_DSN` names a server, and a release is cut only after
they have passed there as well:

```sh
ARANDU_TEST_POSTGRES_DSN='postgres://paulorlima9@localhost:5432/arandu_token_test?sslmode=disable' \
  go test -race -count=1 ./...
```

CI runs the same four gates, and so does the release workflow on the tagged
archive.

## What the manifest declares, and who reads it

`arandu.mod.toml` is a promise, and the check that gives it weight runs here.
Nowhere else does: `aru doctor` audits the tree of the application it is run
inside and never loads a dependency, so the manifest of an installed package is
opened by nothing but that package's own suite.

```toml
name = "hyz-is/token"
framework = ">= 0.67"
profiles = ["conventional", "performance"]

[permissions]
network = false
filesystem = false
exec = false
migrations = true
```

`TestTheDeclaredCapabilitiesAreWhatTheCodeDoes`, in `tests/Unit/audit_test.go`,
compares the four permissions against what the code *calls*, by AST —
`os.WriteFile`, `os.ReadFile`, `filepath.WalkDir`, `exec.Command`, `http.Get`,
`.Do`, `net.Dial`, and a method named `Migrations` on a receiver. It looks at
calls rather than imports because `net/http` is imported by everything that has
a route and says nothing about whether it calls out. A file behind a build tag
is left out, because the compiler never puts it in the module.

Two findings come out of that comparison. The names and severities below are
`aru doctor`'s, from the day an application runs the same comparison over its
own code; here both fail the suite, because `go test` has one outcome:

| finding | severity | what it means |
| --- | --- | --- |
| `permission-not-declared` | error | the code does it and the manifest says `false`. Whoever installed this agreed to a module that does not |
| `permission-not-used` | warning | the manifest says `true` and nothing does it. Asking for more than you need is how a permission model erodes into everyone declaring everything |

So a dependency or a call added here is a line changed in `arandu.mod.toml` in
the same commit. `migrations = true` is the one this package declares, and it is what tells an
installer to run `aru migrate` before deploying.

The `framework` line is a floor, and it is a second declaration of something
`go.mod` already says. Move both together when you bump.

## Adding a dependency

Do not, without an argument. This module goes into other people's builds: a
second `require` is a download and an audit surface for every project that
installs the package, and the framework's own rule is a core with no third-party
dependency beyond `golang.org/x/crypto`.

What is already here is the framework and the components module it is built on:

```sh
export GOWORK=off
go list -m -f '{{if and (not .Indirect) (not .Main)}}{{.Path}} {{.Version}}{{end}}' all
```

If something genuinely has to come in, it goes with a note in the pull request
saying what it does that the framework does not, and the manifest changes in the
same commit if it can reach the network, the filesystem or another process.

## Publishing

A published Go module version is **immutable**. The proxy serves it forever, and
a mistake is corrected by another release, never by moving a tag. That is the
reason `CHANGELOG.md` says so and the reason a migration name is fixed once it
has shipped.

Before tagging:

- the four gates pass with `GOWORK=off`;
- the tests pass on PostgreSQL as well as on SQLite;
- `arandu.mod.toml` matches the code;
- `CHANGELOG.md` has the entry, under the version, in the Keep a Changelog
  sections — `Added`, `Changed`, `Fixed`, `Removed`.

While the version starts with `v0.`, breaking is allowed — freezing a shape this
early is worse. Breaking *quietly* is not. A field that stops existing is a
build that stops in somebody else's repository, weeks later, when they upgrade,
with an error about a struct literal they did not write. Say what it was, what
it is, and what they have to write instead.

Run `apidiff` against the release baseline and enumerate every removal; the CI
step named `api diff against the last release` fails unless `UPGRADE.md` names
each one. A change to the shape of `Config`, `Pair`, `Device`, `Event` or
`Principal` breaks every struct literal of the application that writes one, and
each field that goes is named on its own.

Three changes break an installer without touching a signature, and each one is
worth a line in the changelog:

- **A route name.** URLs are built from names, so a rename is a 404 in a
  template somebody else wrote.
- **A migration name.** Changing what an applied name means leaves the change
  missing everywhere it already ran, and nothing says so.
- **A default.** `DefaultPrefix` and `DefaultPageSize` are what an application
  gets by leaving the field empty, so moving one moves behaviour in every
  project that never mentioned it.

## Reporting a vulnerability

Not in an issue and not in a pull request. `SECURITY.md` has the private
advisory address. Anything that lets a caller reach data a policy did not
authorize is in scope — a handler that reaches a Model or database directly, a
route outside `RequireAuth`, a Model terminal before `Authorize`, disabled
tenant scope, a `Grant` produced without a Policy returning nil, or a field
reaching a response that `Resource` does not list.
