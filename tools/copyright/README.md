# copyright

`copyright` gives an organization a current-year copyright claim in each Go file
changed on the current branch. Run it from the repository root.
By default it prints the edits as a patch and changes no file:

```sh
go run ./tools/copyright -affiliation "SCION Association"
```

`-w` also writes the edits to the files. `git apply` accepts the printed patch too:

```sh
go run ./tools/copyright -w -affiliation "SCION Association"
go run ./tools/copyright -affiliation "SCION Association" | git apply
```

To write the edits through Bazel:

```sh
make copyright-update AFFILIATION="SCION Association"
```

The tool matches `-affiliation` exactly against existing copyright holders.
For example, `Scion Association` and `SCION Association` are different holders.
The value cannot contain a comma because commas separate holders on a shared line.

## Which files

The tool processes every Go file that differs between the working tree and the
branch's merge base with `upstream/master`. If `upstream/master` does not exist,
it uses `origin/master`. Committed, staged, unstaged, and untracked changes count.
Deleted files do not.

A fork names the main repository `upstream`, as [doc/dev/git.rst](../../doc/dev/git.rst)
describes. The fork's `origin/master` may lag behind `upstream/master`, which would
make upstream changes appear to belong to the current branch. The tool returns an
error if neither branch exists.

## What changes

Each updated file contains one current-year claim for the organization:

- If a line already claims the current year or a later year for the organization,
  the file does not change.
- Otherwise, the newest line naming the organization moves to the current year.
  The tool removes the organization from its older claims and deletes any claim
  left without a holder. A line with one holder keeps its position and only its
  year changes. A shared line splits, and the other holders retain their original year:

  ```txt
  // Copyright 2017 ETH Zurich
  // Copyright 2018 ETH Zurich, Anapaya Systems
  // Copyright 2025 SCION Association
  ```

  becomes, for ETH Zurich:

  ```txt
  // Copyright 2026 ETH Zurich
  // Copyright 2018 Anapaya Systems
  // Copyright 2025 SCION Association
  ```

- If no line names the organization, the tool adds
  `// Copyright <year> <organization>` below the existing claims.

Claims retain their order. Years never decrease. Other lines remain unchanged.

The patch goes to stdout:

```diff
diff --git a/control/beaconing/writer.go b/control/beaconing/writer.go
--- a/control/beaconing/writer.go
+++ b/control/beaconing/writer.go
@@ -1,5 +1,5 @@
 // Copyright 2019 Anapaya Systems
-// Copyright 2025 SCION Association
+// Copyright 2026 SCION Association
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
```

The skipped files and a summary go to stderr:

```txt
would update 1 of 1 Go file changed since the merge base with upstream/master
run `go run ./tools/copyright -w -affiliation "SCION Association"` to write the patch
```

## Files it leaves alone

The tool reports and skips:

- Generated files.
- Headers with a copyright notice in any form other than
  `// Copyright <year> <organization>[, <organization>...]`. Examples include
  `// Copyright (c) 2016 Max Mustermann` and
  `//  Copyright 2020 Some Other Labs, Inc.` (two spaces).
- Files with no copyright header or Apache license block. The tool can add a
  claim above an existing license block, but it does not add a missing license.
  `goheader` reports missing licenses.
- Files where a copyright claim follows other text in the leading comment block.
  This includes an SPDX tag above the claim. Put the SPDX tag below the license
  block, as in `private/underlay/ebpf`.

The tool accepts any holder in a correctly formed claim.
For example, it adds the requested organization's claim below
`// Copyright 2013 The Prometheus Authors`.

## Not part of make lint

`goheader` in `.golangci.yml` checks the header format and license text.
It doesn't track who changed the file.

`make lint` and CI do not run this tool. A missing claim does not block a pull request.
