# copyright

See [doc.go](doc.go) for documentation, or use `go doc ./tools/copyright`.

By default it reports how many files are out of date, and which identities it could not
attribute. Under `-v`, every line it adds or moves cites the contribution behind it:

```
private/storage/beacon/sqlite/db.go
    - // Copyright 2019 Anapaya Systems
    + // Copyright 2025 Anapaya Systems    (roos@anapaya.net, 2025-09-30 38e79c43f)
    + // Copyright 2025 SCION Association  (roman.scharkov@gmail.com, 2025-02-12 33de3e514)
```

## What it will not do

The tool only adds claims and moves years forward. It never drops a claim or
moves a year back, because git history is not the only evidence of authorship.

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
Without a `user.email`, the tool stops with an error. To go by git history alone,
pass `-committed-only`, which needs no identity.

## affiliations.json

Resolution order for an (email, year) pair:

1. an entry in `contributors` whose `emails` contains the address
2. the domain of the address in `domains`
3. otherwise unaffiliated: nothing is claimed

Affiliations are time-bounded, because people change employer while keeping the
same address:

```json
{
  "name": "Some Contributor",
  "emails": ["some@example.com", "contributor@scion.org"],
  "affiliations": [
    {"org": "ETH Zurich", "from": 2018, "until": 2022},
    {"org": "SCION Association", "from": 2023}
  ]
}
```

`from` and `until` are inclusive years and either may be omitted for an open end.
A year covered by no affiliation claims nothing, which is how work from
before a contributor joined any of these organizations stays unclaimed.

`ignoreEmails` drops bots. There is deliberately no list of excluded paths:
which files are ours to edit is read from each file's header.
Nothing needs keeping in sync as files come and go.

Adding an entry can only add claims,
which makes it safe to re-run the tool after editing the configuration.
`go test ./tools/copyright` validates the embedded configuration.

## Not part of make lint

`goheader` in `.golangci.yml` enforces the shape of the header and the presence
of the license text. It does not know who worked on the file.

`make copyright-check` reports what is out of date; `make copyright-update` rewrites it.
Neither is wired into `make lint`, deliberately, to avoid slowing down CI.
