# Upgrade Guide

## Unreleased

## v0.1.0

The first release; there is nothing to upgrade from.

To install it, wire it as the README says and run `aru migrate` once before the
application serves: the migration `20261031_0001_create_token_tables` creates
`token_credentials` and `token_devices`.

