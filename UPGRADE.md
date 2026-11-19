# Upgrade Guide

## Unreleased

## v0.1.1

Run `aru migrate`: `20261119_0001_widen_token_time_precision` raises the
instants of `token_credentials` and `token_devices` from whole seconds to
microseconds where a database was migrated before Hesape v0.67.0. On PostgreSQL
it changes the type modifier only and rewrites neither the tables nor their
indexes; on MySQL the columns are restated with `MODIFY`, which may copy the
tables. No credential or device changes. A process still running the previous
binary may see PostgreSQL refuse a cached plan over the tables once per
connection ("cached plan must not change result type"): migrate before the new
binary starts. No symbol of this package changes.

## v0.1.0

The first release; there is nothing to upgrade from.

To install it, wire it as the README says and run `aru migrate` once before the
application serves: the migration `20261031_0001_create_token_tables` creates
`token_credentials` and `token_devices`.

