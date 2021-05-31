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

package tc

import (
	"golang.org/x/net/ipv4"
)

type StrictPriorityScheduler struct{}

// Schedule schedules packets based on a strict hierarchy, where a message from a
// queue is only scheduled if all higher priority queues are empty.
// The priorities are: COLIBRI > BFD > OHP > EPIC > SCMP > SCION > Others.
func (s *StrictPriorityScheduler) Schedule(qs *Queues) ([]ipv4.Message, error) {
	read := 0
	n, err := qs.dequeue(ClsColibri, outputBatchCnt-read, qs.writeBuffer[read:])
	if err != nil {
		return nil, err
	}
	read = read + n

	n, err = qs.dequeue(ClsBfd, outputBatchCnt-read, qs.writeBuffer[read:])
	if err != nil {
		return nil, err
	}
	read = read + n

	n, err = qs.dequeue(ClsOhp, outputBatchCnt-read, qs.writeBuffer[read:])
	if err != nil {
		return nil, err
	}
	read = read + n

	n, err = qs.dequeue(ClsEpic, outputBatchCnt-read, qs.writeBuffer[read:])
	if err != nil {
		return nil, err
	}
	read = read + n

	n, err = qs.dequeue(ClsScmp, outputBatchCnt-read, qs.writeBuffer[read:])
	if err != nil {
		return nil, err
	}
	read = read + n

	n, err = qs.dequeue(ClsScion, outputBatchCnt-read, qs.writeBuffer[read:])
	if err != nil {
		return nil, err
	}
	read = read + n

	n, err = qs.dequeue(ClsOthers, outputBatchCnt-read, qs.writeBuffer[read:])
	if err != nil {
		return nil, err
	}
	read = read + n

	if read > 0 {
		qs.setToNonempty()
	}

	return qs.writeBuffer[:read], nil
}
