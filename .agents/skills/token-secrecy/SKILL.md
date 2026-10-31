---
name: token-secrecy
description: Keep tokens out of everything. Use when a change touches Secret, Pair, Revealed, an error message, a log or print line, an Event, a String or LogValue or MarshalJSON method, the Reveal call, the digest, a test that prints a pair, or when the request is to "log the token", "include the token in the error", "debug why the token fails", "print the pair", "return the pair as JSON", "store the token", "show the token again", or "the leak test fails". Covers why a Secret is a struct holding a pointer, the single door that turns one into a string, what an error may say, and how the leak test looks for tokens.
license: MIT
---

# Tokens never leave except through one door

A token is shown once, in the `Pair` that issues it. After that the only thing
that exists is its SHA-256 digest. Nothing in this package prints, logs, formats,
encodes or returns one except `Pair.Reveal`, in `secret.go`, which builds the body
of the answer that hands the tokens to their owner.

## Why Secret is built the way it is

`Secret` is a struct holding a **pointer** to the string. Two properties follow,
and both were found by a test, not by thought:

- `string(secret)` does not compile.
- When `fmt` is given a verb that does not fit (`%p`, `%d` on a struct), it prints
  the fields itself and calls no `Format`, `String` or `LogValue` on the way. A
  string field would be printed in the open; a pointer field prints as an address.
  `Revealed` holds its body behind a pointer for the same reason.

`Secret.Format` answers `[redacted]` for every verb, and `MarshalJSON`,
`MarshalText`, `LogValue`, `String` and `GoString` do the same.

## What an error may say

An error says what happened, never to whom or with what. No token, no digest, no
identifier of a user in the text. `ErrInvalidToken` is one error for a token that
was never issued, expired, was revoked, or is the other kind, because a caller
told which of them it was learns what exists.

A store error is wrapped with `%w` as it came; the driver's message does not carry
the arguments of the statement.

## When you add something

- A new type that holds a token holds it as a `Secret`, and gets its own entry in
  `TestNoTokenIsEverStoredLoggedPrintedOrEncoded` and `TestEveryVerbAndEncodingOfAPairHidesTheTokens`.
- A new place that needs the string calls `Reveal` only if it is the body of the
  answer to the owner. `TestAnAccessTokenLeavesThroughOneDoor` fails otherwise.
- A statement is handed `digest`, never a variable named `token`, `access`,
  `refresh`, `raw` or `bearer` (`TestNoStatementIsHandedAToken`).
- No `fmt.Print*`, `log.*` or `slog.*` in the package
  (`TestNothingInThePackageLogsPrintsOrReadsAHeaderOfTheClient`). What the
  application should know goes out as an `Event`.

## When a token fails and you need to know why

Do not print it. The digest is safe to look up by (`token.DigestOf(t).String()`
against `token_credentials.digest`), and the row says `kind`, `expires_at`,
`revoked_at` and `revoked_reason`: `rotated` is an exchanged refresh token, and
its reuse is a theft; anything else is only a revocation.
