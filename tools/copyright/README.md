# copyright

Gives your organization a copyright claim for the current year in every Go file
changed on your branch. From the repository root:

```sh
go run ./tools/copyright -affiliation "SCION Association"
```

`make copyright-update` runs the same through Bazel:

```sh
make copyright-update AFFILIATION="SCION Association"
```

`-affiliation` must be one of the names in [organizations.go](organizations.go).
If yours is missing, add it there.

## Which files

Every Go file that differs between the working tree and the commit where the branch
left `upstream/master`, or `origin/master` if there is no `upstream/master`.
Committed, staged, unstaged and untracked changes all count; deleted files do not.

A fork names the main repository `upstream`, as [doc/dev/git.rst](../../doc/dev/git.rst)
describes. There `origin/master` is the fork's own and lags behind unless it is synced,
and every upstream commit it lacks would count as a change of the branch.
If neither branch exists, the tool stops with an error.

## What changes

The tool makes the smallest edit that gives the organization a claim for the current year:

- A line that already claims this year or later for the organization: nothing changes.
- A line the organization holds alone, for an earlier year: the year changes in place,
  and nothing else on the line. Of several such lines, the newest one changes.
- Otherwise `// Copyright <year> <organization>` is added below the existing claims.
  A shared line, such as `// Copyright 2018 ETH Zurich, Anapaya Systems`, is never
  edited: it also states the year of the other holder.

Claims are never reordered, removed or moved back. Every other line stays as it was.

The report lists each edit:

```txt
control/beaconing/writer.go
    - // Copyright 2025 SCION Association
    + // Copyright 2026 SCION Association
dispatcher/config/config.go
    + // Copyright 2026 SCION Association

updated 2 of 2 Go files changed since the merge base with upstream/master
```

## Files it leaves alone

The report lists these with the reason:

- Generated files.
- Third-party notices: a header claiming copyright in any form other than
  `// Copyright <year> <organization>`. `// MIT License`,
  `// Copyright (c) 2016 Max Mustermann` and `//  Copyright 2020 Some Other Labs, Inc.`
  (two spaces) all occur here.
- A well-formed line held by a holder not in organizations.go,
  such as `// Copyright 2013 The Prometheus Authors`.
- Files with no header. A claim goes above an Apache license block,
  and a missing license is not invented; `goheader` flags those.
- Files whose header does not open with the copyright line, an SPDX tag above it included.
  The parser reads claims from the first line of the leading comment block,
  so a tag belongs below the license block, as in `private/underlay/ebpf`.

## Not part of make lint

`goheader` in `.golangci.yml` enforces the shape of the header and the presence
of the license text. It does not know who worked on the file.

The tool is not wired into `make lint` or CI, deliberately, so it does not block PRs
whose author does not want to update the claims.
