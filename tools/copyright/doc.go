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
// affiliations.json says who belongs to which organization, not when.
// -dates points at an optional file giving the days each affiliation covers,
// which matters for people who changed employer while keeping the same address.
// Without it, an affiliation covers every day.
//
// The "since" day in affiliations.json freezes the history before it.
// Those contributions are already recorded in the headers, and reading them again
// without the dates could only claim them for the wrong organization.
// Passing -dates lifts the cutoff, since the dates are what date that history;
// a configuration with no cutoff at all therefore requires them.
// Apply the dates and advance the cutoff in the same change,
// and no later run touches settled claims.
//
// Each line the report adds or moves cites the contribution it rests on:
// the author, and the commit and date it came from, or "uncommitted".
//
// Claims are only added or moved forward, never dropped and never moved back,
// because git history is not the only evidence of authorship.
//
// -verify turns that around and checks the claims already in the headers,
// reporting every organization no contribution accounts for, and removing it under -w.
// It needs -dates, since the cutoff hides the contributions the older
// claims rest on, and it leaves a file's claims as given when an identity that
// touched it has no known affiliation. Even then the answer is a question,
// not a verdict: code moves between files by hand, and work can predate this repository.
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
//	# with the dates the affiliations held for, which puts the whole history in scope:
//	# advance "since" in affiliations.json in the same change
//	go run ./tools/copyright -w -dates tools/copyright/affiliation-dates.json
//	# ask which claims no contribution accounts for, without touching anything
//	go run ./tools/copyright -v -verify -dates tools/copyright/affiliation-dates.json
package main
