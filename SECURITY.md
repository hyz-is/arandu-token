# Security policy

## Supported versions

The latest minor release of Arandu Token receives security fixes. Older minor
releases do not: a published Go module version is immutable, so a fix is a new
release rather than a moved tag.

## Reporting a vulnerability

Report it privately, through GitHub's advisory form:

<https://github.com/hyz-is/arandu-token/security/advisories/new>

Do not open a public issue and do not describe the problem in a pull request.
A report that arrives in public is a report every reader of this repository can
act on before there is a release to upgrade to.

Include what you need to reproduce it: the version, the wiring, and the request
or call that triggers it.

Expect an acknowledgement within a few days. If the report is confirmed, the
fix, the release and the advisory are published together, and you are credited
unless you ask not to be.

## What is in scope

Anything that lets a caller act as somebody it is not, or keeps acting after it
should not be able to. In particular:

- a token, or the random part of one, that reaches a table, an error, a log
  line, a `String()` or `LogValue`, or a JSON other than `Pair.Reveal`;
- a way to use a refresh token twice without the session being revoked, or an
  exchange in which two simultaneous callers both win;
- a token that still resolves after it expired, was revoked, was rotated, or
  after its session was switched to another workspace;
- a call that acts on a device or a session of a user other than the one it was
  given, including the same device identifier on two accounts;
- a way to make the module decide a tenant of data, or to put a principal on a
  context without the middleware;
- a way to make the throttle forget a lockout in force, or to grow its table
  without bound;
- an address taken from a header the client writes.

## What is not

- A vulnerability in the framework itself. Report that to the framework.
- An application that does not revalidate the Membership in its `SubjectFunc`, or
  that lets a user list or revoke the devices of another. The module takes the
  user it acts on from its caller; who may ask is the application's.
- A sign-in throttle used behind several instances without a shared store. The
  `Limiter` lives in one process and says so.
