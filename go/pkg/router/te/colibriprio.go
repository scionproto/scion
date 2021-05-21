// Copyright 2021 ETH Zurich
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

// Package te adds traffic engineering capabilities to the border router.
// Traffic engineering can be enabled/disabled in 'scion/go/posix-router/main.go'.
// The purpose of this package is to demonstrate the feasibility of integrating
// scheduling into the border router. Only basic scheduling algorithms are
// implemented, more elaborate ones might be necessary in the future.
package te

import (
	"golang.org/x/net/ipv4"
)

type ColibriPriorityScheduler struct{}

// Schedule gives priority to Colibri packets, but also includes up to one packet of
// each other traffic class.
func (s *ColibriPriorityScheduler) Schedule(qs *Queues) ([]ipv4.Message, error) {
	// Prioritize Colibri packets
	nrQueues := len(qs.mapping)
	read := 0
	n, err := qs.dequeue(ClsColibri, outputBatchCnt-nrQueues, qs.writeBuffer[read:])
	if err != nil {
		return nil, err
	}
	read = read + n

	// Remaining classes are scheduled using round-robin (including one Colibri packet)
	for cls := range qs.mapping {
		n, err := qs.dequeue(cls, 1, qs.writeBuffer[read:])
		if err != nil {
			return nil, err
		}
		read = read + n
	}

	if read > 0 {
		qs.setToNonempty()
	}

	return qs.writeBuffer[:read], nil
}
