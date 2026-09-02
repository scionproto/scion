# copyright

See [doc.go](doc.go), or `go doc ./tools/copyright`.

By default it reports how many files are out of date, and which identities it could not
attribute. Under `-v`, every line it adds or moves cites the contribution behind it:

```txt
private/storage/beacon/sqlite/db.go
    - // Copyright 2019 Anapaya Systems
    + // Copyright 2025 Anapaya Systems    (roos@anapaya.net, 2025-09-30 38e79c43f)
    + // Copyright 2025 SCION Association  (roman.scharkov@gmail.com, 2025-02-12 33de3e514)
```

## What it will not do

It only adds claims and moves years forward, never drops one or moves a year back:
git history is not the only evidence of authorship.
`-verify` is the only way to ask it to remove claims.

Files it declines to touch, all listed under `-v`:

- Generated files.
- Third-party notices: a header claiming copyright in any form other than
  `// Copyright <year> <configured organization>`. `// MIT License`,
  `// Copyright (c) 2016 Max Mustermann` and `//  Copyright 2020 Some Other Labs, Inc.`
  (two spaces) all occur here.
- A well-formed line held by an undeclared organization,
  such as `// Copyright 2013 The Prometheus Authors`.
- Files with no header. Claims go above an Apache license block,
  and a missing license is not invented; `goheader` flags those.
- Files whose header does not open with the copyright line, an SPDX tag above it included.
  The parser reads claims from the first line of the leading comment block,
  so a tag belongs below the license block, as in `private/underlay/ebpf`.

An identity with no known affiliation claims nothing, and is reported.
Leaving an identity out is safe. Guessing its affiliation is not.

Uncommitted work is attributed to `git config user.email` and the current year;
having no date of its own, the affiliation is read at the end of that year.
Without a `user.email` the tool stops. `-committed-only` needs no identity.

## affiliations.json

Resolution order for an (email, date) pair:

1. an entry in `contributors` whose `emails` contains the address
2. the domain of the address in `domains`
3. otherwise nothing is claimed

```json
{
  "name": "Max Mustermann",
  "emails": ["max.m@example.com", "max@another.org"],
  "affiliation": "Muster Org"
}
```

One organization per person, undated, so it answers for every day that address
contributed. It lists the people contributing now: an entry whose addresses have
not appeared for a year is dropped. Earlier spans live in the file below, which
is neither embedded nor read by default — the repository does not publish when
someone worked where.

`ignoreEmails` drops bots. There is deliberately no list of excluded paths:
which files are ours to edit is read from each file's header.

Adding an entry can only add claims, so re-running after an edit is safe.
`go test ./tools/copyright` validates the embedded configuration.

## affiliation-history.json

People change employer while keeping the same address, and the snapshot has
dropped others outright. `-history` points at a file of dated spans that
replaces the contributors of affiliations.json, so it carries its own addresses:

```json
[
  {
    "name": "Some Contributor",
    "emails": ["some@example.com", "contributor@scion.org"],
    "affiliations": [
      {"org": "ETH Zurich", "from": "2018-09-01", "until": "2022-11-30"},
      {"org": "SCION Association", "from": "2022-12-01"}
    ]
  }
]
```

```sh
go run ./tools/copyright -w -history tools/copyright/affiliation-history.json
```

`.gitignore` reserves that path, but the file may live anywhere. Through `make`,
give an absolute path: `bazel run` does not start in the repository root.

`from` and `until` are inclusive `YYYY-MM-DD` days. `from` is required,
so no span reaches further back than meant; `until` may be omitted while an
affiliation holds. Where the day is unknown, `-01-01` and `-12-31` bound the year.
A day no span covers claims nothing.

`name` only labels the entry; contributions are matched by address.
The file answers alone, so everyone whose work is to be claimed belongs in it,
the people in affiliations.json included; an address it omits is reported as a gap.
Its organizations must be declared in affiliations.json, but need not be current ones.
Only `organizations`, `domains` and `ignoreEmails` are still read from there:
those hold whenever an address was used.

Running without `-history` claims more: someone who left an organization keeps
claiming for it, and the people the snapshot dropped claim nothing.

## Claims nothing accounts for

By default an existing claim is taken as given. `-verify` checks them too,
and reports every organization no contribution to that file accounts for:

```txt
pkg/private/util/fs.go
    - // Copyright 2019 ETH Zurich       (no contribution from ETH Zurich)
    + // Copyright 2022 Anapaya Systems  (roos@anapaya.net, 2022-03-12 15d455f11)
```

Read-only without `-w`:

```sh
make copyright-check COPYRIGHT_FLAGS="-v -verify -history $PWD/tools/copyright/affiliation-history.json" > report.txt 2>/dev/null
```

A shared line keeps its other holders, and no file loses all its claims: a file
is only processed when it has contributions, and those get claims of their own.

Two limits:

- It needs `-history`: affiliations.json says where people work today,
  so a claim for an organization its contributor has left would look unaccounted for.
- It leaves a file alone when someone who touched it has no known affiliation:
  that person may be who a claim rests on. `-v` lists those files.

**A claim with nothing behind it is a question, not a verdict.** Code gets copied
between files by hand, work can predate this repository, and a commit can carry
someone else's patch. Read the report and decide; don't pipe it into `-w`.

## Not part of make lint

`goheader` in `.golangci.yml` enforces the shape of the header and the presence
of the license text. It does not know who worked on the file.

`make copyright-check` reports what is out of date; `make copyright-update` rewrites it.
