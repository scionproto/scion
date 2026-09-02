# copyright

See [doc.go](doc.go) for documentation, or use `go doc ./tools/copyright`.

By default it reports how many files are out of date, and which identities it could not
attribute. Under `-v`, every line it adds or moves cites the contribution behind it:

```txt
private/storage/beacon/sqlite/db.go
    - // Copyright 2019 Anapaya Systems
    + // Copyright 2025 Anapaya Systems    (roos@anapaya.net, 2025-09-30 38e79c43f)
    + // Copyright 2025 SCION Association  (roman.scharkov@gmail.com, 2025-02-12 33de3e514)
```

## What it will not do

The tool only adds claims and moves years forward. It never drops a claim or
moves a year back, because git history is not the only evidence of authorship.
`-verify` is the one way to ask it to drop one; see below.

It declines in these cases: `-v` lists them, and logs each file it rewrites:

- Generated files.
- Third-party notices: a header that claims copyright in any form other than
  `// Copyright <year> <configured organization>`. `// MIT License`,
  `// Copyright (c) 2016 Max Mustermann` and `//  Copyright 2020 Some Other Labs, Inc.`
  (two spaces) all occur in this repository. Such a file is left untouched.
- A well-formed line held by an organization the configuration does not declare,
  such as `// Copyright 2013 The Prometheus Authors`.
- Files with no header at all. Claims go above an Apache license block, but a
  missing license is not invented. `goheader` flags those.
- Files whose header does not open with the copyright line, an SPDX tag above
  it included. The parser reads claims from the first line of the leading
  comment block, so a tag belongs in a comment of its own below the license
  block, which is what `private/underlay/ebpf` does.

An identity with no known affiliation contributes no claim, and is reported so
it can be added to the configuration.
Leaving an identity out is safe. Guessing its affiliation is not.

Uncommitted work is attributed to `git config user.email` and the current year.
It carries no date of its own, so the author's affiliation is read at the end of
that year. Without a `user.email`, the tool stops with an error.
To go by git history alone, pass `-committed-only`, which needs no identity.

## affiliations.json

Resolution order for an (email, date) pair:

1. an entry in `contributors` whose `emails` contains the address
2. the domain of the address in `domains`
3. otherwise unaffiliated: nothing is claimed

An affiliation is an organization name, and carries no date:

```json
{
  "name": "Some Contributor",
  "emails": ["some@example.com", "contributor@scion.org"],
  "affiliations": ["ETH Zurich", "SCION Association"]
}
```

That is all this file says. The dates live in a separate file, described below,
which is neither embedded nor read by default: the repository does not
publish when someone worked where. Without it the first organization listed
answers for every day that address contributed, and `since` bounds how far
back such a run may look.

`ignoreEmails` drops bots. There is deliberately no list of excluded paths:
which files are ours to edit is read from each file's header.
Nothing needs keeping in sync as files come and go.

Adding an entry can only add claims,
which makes it safe to re-run the tool after editing the configuration.
`go test ./tools/copyright` validates the embedded configuration.

## Affiliation dates

People change employer while keeping the same address, and the day of the move
splits that year's commits between the two organizations. `-dates` points at a
file that records those spans:

```json
[
  {
    "name": "Some Contributor",
    "affiliations": [
      {"org": "ETH Zurich", "from": "2018-09-01", "until": "2022-11-30"},
      {"org": "SCION Association", "from": "2022-12-01"}
    ]
  }
]
```

```sh
go run ./tools/copyright -w -dates tools/copyright/affiliation-dates.json
```

`.gitignore` reserves that path, so the file can sit next to the configuration
uncommitted, but it may live anywhere. Through `make`, give an absolute path:
`bazel run` does not start in the repository root.

`from` and `until` are inclusive `YYYY-MM-DD` dates and either may be omitted
for an open end. Where the exact day is unknown, `-01-01` and `-12-31` bound the
year without claiming more than it. A day covered by no affiliation claims nothing,
which is how work from before a contributor joined any of these
organizations stays unclaimed.

The file is a list of contributors that affiliations.json declares, named by
`name`, and it must give each of them the same organizations it does, in the
order they should be tried. Dating someone it does not declare, or leaving out
an organization it gives them, is an error rather than a silent change of
holder.

Running without `-dates` claims more than running with it: a contributor who
left an organization keeps claiming for it. The `since` cutoff keeps such a run
off the history where that would show. See below.

## The `since` cutoff

`since` in affiliations.json is a `YYYY-MM-DD` day. Contributions made before it
are not attributed at all, so a plain `make copyright-update` cannot reach the
history the headers already record:

```json
{
  "since": "2026-09-01",
  "organizations": ["..."]
}
```

Claims are only ever added. A run without `-dates` reads every affiliation as
covering every day, so it can credit an organization the author had left, and
that line then stays even once the dates are supplied. A cutoff puts that
history out of reach instead.

Passing `-dates` lifts the cutoff, since the dates are what date that history.
`since` then moves to the day of that run:

```sh
go run ./tools/copyright -w -dates tools/copyright/affiliation-dates.json
```

A configuration with no `since` at all is an error without `-dates`: that run
puts the whole history in scope with nothing to date it by, which is the case
that misattributes work.

The invariant: affiliations.json describes today, and the dates file describes
what happened before `since`. When someone changes employer, date the move in
the dates file, run with `-dates`, and advance `since` in the same commit.

## Claims nothing accounts for

By default an existing claim is taken as given. `-verify` checks them too,
and reports every organization that no contribution to that file accounts for:

```txt
pkg/private/util/fs.go
    - // Copyright 2019 ETH Zurich       (no contribution from ETH Zurich)
    + // Copyright 2022 Anapaya Systems  (roos@anapaya.net, 2022-03-12 15d455f11)
```

Read-only without `-w`, applied with it, like every other change:

```sh
make copyright-check COPYRIGHT_FLAGS="-v -verify -dates $PWD/tools/copyright/affiliation-dates.json" > report.txt 2>/dev/null
```

A shared line keeps its other holders, and no file loses all its claims: a file
is only processed when it has contributions, and those get claims of their own.

Two limits, both on purpose:

- It needs `-dates`. The `since` cutoff hides the older contributions, so without
  the dates every old claim would look unaccounted for.
- It leaves a file's claims alone when someone who touched it has no known
  affiliation: that person may be who a claim rests on. `-v` lists those files.

**A claim with nothing behind it is a question, not a verdict.** Code gets copied
between files by hand, work can predate this repository, and a commit can carry
someone else's patch. Read the report and decide; don't pipe it into `-w`.

## Not part of make lint

`goheader` in `.golangci.yml` enforces the shape of the header and the presence
of the license text. It does not know who worked on the file.

`make copyright-check` reports what is out of date; `make copyright-update` rewrites it.
