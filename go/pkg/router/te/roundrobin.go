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

package te

import (
	"golang.org/x/net/ipv4"
)

type RoundRobinScheduler struct{}

// Schedule schedules the packets based on round-robin over all queues.
func (s *RoundRobinScheduler) Schedule(qs *Queues) ([]ipv4.Message, error) {
	read := 0
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
