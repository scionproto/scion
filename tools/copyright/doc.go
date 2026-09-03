// Copyright 2026 SCION Association
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Tool copyright keeps the copyright lines of Go files in step with who
// worked on them.
//
// For every file it collects the identities that changed it, in git history and
// in the working tree, maps each identity to an organization via the embedded
// affiliations.json, and gives that organization a claim for the most recent
// year it contributed.
//
// affiliations.json is undated: it says where people work now, so an affiliation
// covers every day, and someone who has not contributed in a year is dropped.
// A run therefore reads only the commits -base does not reach, the work on this branch,
// where that snapshot is current by definition. Everything -base reaches is settled:
// its claims are in the headers already, and reading it again undated could only
// claim it for whoever its author works for today.
// -base defaults to origin/master, and an empty one reads the whole history.
//
// -history points at an optional file that dates the affiliations instead,
// for a rewrite of older history: people change employer, and the snapshot has
// dropped others outright. It replaces that snapshot rather than refining it,
// so it carries its own addresses; only the organizations, domains and ignored
// addresses still come from affiliations.json. Every span needs a "from" day.
// Dating every revision is what puts the whole history back in scope,
// so -history ignores -base.
//
// Each line the report adds or moves cites the contribution it rests on:
// the author, and the commit and date it came from, or "uncommitted".
//
// Claims are only added or moved forward, never dropped and never moved back,
// because git history is not the only evidence of authorship.
//
// -verify turns that around and checks the claims already in the headers,
// reporting every organization no contribution accounts for, and removing it under -w.
// It needs -history, since the snapshot alone finds nothing behind a claim for an
// organization its contributor has left, and it leaves a file's claims as given
// when an identity that touched it has no known affiliation. Even then the answer
// is a question, not a verdict: code moves between files by hand,
// and work can predate this repository.
// Read the report before writing it.
//
// Uncommitted work is credited to git config user.email, and the author's
// affiliation is read at the end of the year it is claimed for.
// Without an address the tool stops with an error,
// rather than leave that work out and call every header up to date.
// Use -committed-only to ask for git history alone.
//
// Some files are left untouched: generated files, third-party notices,
// headers whose holder is an organization the configuration does not declare,
// and files carrying no header at all.
//
// By default the report is a count of the files that are out of date.
// The -v flag lists them, with the contribution behind every line it adds or moves,
// and lists the files it left untouched. Identities that have no known affiliation,
// and so claim nothing, are listed either way:
// the run cannot account for their work until they are added to the configuration.
//
// The run covers the directory it starts in and everything below it.
// Starting from a package updates that package; starting from the
// repository root updates everything.
//
//	# report what is out of date here and below, exit non-zero if anything is
//	go run ./tools/copyright
//	# bring this subtree's headers up to date
//	go run ./tools/copyright -w
//	# a subtree somewhere else, or single files within it
//	go run ./tools/copyright -w -dir router
//	go run ./tools/copyright -w -dir router dataplane.go svc.go
//	# rewrite older history from the days the affiliations held for,
//	# in place of the snapshot in affiliations.json
//	go run ./tools/copyright -w -history tools/copyright/affiliation-history.json
//	# ask which claims no contribution accounts for, without touching anything
//	go run ./tools/copyright -v -verify -history tools/copyright/affiliation-history.json
package main
