# Skills

Procedures an assistant follows when working on this package.

They live in `.agents/skills/<name>/SKILL.md`, which is the path the coding
assistants read from — Cursor, Codex, Cline, Copilot, Gemini CLI, Amp, OpenCode,
Warp, Zed and the rest all look there. It is one directory rather than a file
per vendor, so a skill written once is read by whatever this package is being
written with.

Each file opens with frontmatter carrying a `name` and a `description`. The
`name` has to equal the directory name exactly, or the skill is not loaded. The
description is what a tool reads to decide whether the skill is relevant, so it
names the situation you are in rather than the topic it covers.

| skill | when it fires |
| --- | --- |
| `token-secrecy` | anything that touches a `Secret`, a `Pair`, an error message, a log line, an `Event`, or a test that prints a token |
| `token-module` | adding a service call, a config field, a column, a migration, an event, or changing the middleware or the throttle |
| `token-release` | the gates, the manifest, a dependency, a version, a tag |
| `token-vault-notes` | writing the note, the gap or the journal entry, when this checkout sits inside the Arandu Obsidian vault |
| `token-package` | installing and wiring this package **into an application**, and using it there |

The last one has a different audience from the other four, and that is on
purpose: it travels with the package so that an assistant working in somebody
else's project — the one running `go get` — has the wiring, the migration step
and the rules about tokens in front of it instead of guessing.

Its frontmatter says so, under `metadata`, with `audience: app`. That line is
what `aru skills:sync` reads to copy the skill into an application whose
`go.mod` requires this package, and no other skill here carries it: an
application that received the release procedure would follow it.

`token-vault-notes` fires on a condition rather than on a task: it applies
only when `MOC-arandu.md`, `plans/cmd/audit-vault/` and `45-modules/` are actually
beside this checkout, and says to stop when they are not.
