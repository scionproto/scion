// Copyright 2019 Anapaya Systems
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

package seghandler

import "github.com/scionproto/scion/go/lib/ctrl/path_mgmt"

// Stats provides statistics about handling segments.
type Stats struct {
	// SegDB contains stats about segment insertions/updates.
	SegDB SegStats
	// VerifiedSegs contains all segments that were successfully verified.
	VerifiedSegs []*SegWithHP
	// StoredRevs contains all revocations that were verified and stored.
	StoredRevs []*path_mgmt.SignedRevInfo
	// VerifiedRevs contains all revocations that were verified.
	VerifiedRevs []*path_mgmt.SignedRevInfo
}

func (s *Stats) addStoredSegs(segs SegStats) {
	s.SegDB.InsertedSegs = append(s.SegDB.InsertedSegs, segs.InsertedSegs...)
	s.SegDB.UpdatedSegs = append(s.SegDB.UpdatedSegs, segs.UpdatedSegs...)
}

// ProcessedResult is the result of handling a segment reply.
type ProcessedResult struct {
	early      chan int
	full       chan struct{}
	stats      Stats
	revs       []*path_mgmt.SignedRevInfo
	err        error
	verifyErrs []error
}

// EarlyTriggerProcessed returns a channel that will contain the number of
// successfully stored segments once it is done processing the early trigger.
func (r *ProcessedResult) EarlyTriggerProcessed() <-chan int {
	return r.early
}

// FullReplyProcessed returns a channel that will be closed once the full reply
// has been processed.
func (r *ProcessedResult) FullReplyProcessed() <-chan struct{} {
	return r.full
}

// Stats provides insights about storage and verification of segments.
func (r *ProcessedResult) Stats() Stats {
	return r.stats
}

// Err indicates the error that happened when storing the segments. This should
// only be accessed after FullReplyProcessed channel has been closed.
func (r *ProcessedResult) Err() error {
	return r.err
}

// VerificationErrors returns the list of verification errors that happened.
func (r *ProcessedResult) VerificationErrors() []error {
	return r.verifyErrs
}
