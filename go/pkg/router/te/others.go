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

type OthersOnlyScheduler struct{}

// Schedule only forwards packets from the 'Others' queue, all other queues are ignored.
func (s *OthersOnlyScheduler) Schedule(qs *Queues) ([]ipv4.Message, error) {
	read, err := qs.dequeue(ClsOthers, outputBatchCnt, qs.writeBuffer)
	if err != nil {
		return nil, err
	}

	if read > 0 {
		qs.setToNonempty()
	}

	return qs.writeBuffer[:read], nil
}
