// Copyright 2018 ETH Zurich
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

package pathmgr

import (
	"strings"

	"github.com/scionproto/scion/go/lib/sciond"
)

func buildSDAnswer(pathStrings ...string) *sciond.PathReply {
	reply := &sciond.PathReply{
		ErrorCode: sciond.ErrorOk,
		Entries:   make([]sciond.PathReplyEntry, len(pathStrings)),
	}
	for i, pathString := range pathStrings {
		reply.Entries[i] = sciond.PathReplyEntry{
			Path: &sciond.FwdPathMeta{
				Interfaces: mustParseMultiplePI(strings.Split(pathString, " ")),
			},
		}
	}
	return reply
}

func mustParseMultiplePI(strs []string) []sciond.PathInterface {
	var pis []sciond.PathInterface
	for _, str := range strs {
		pis = append(pis, mustParsePI(str))
	}
	return pis
}

func mustParsePI(str string) sciond.PathInterface {
	pi, err := sciond.NewPathInterface(str)
	if err != nil {
		panic(err)
	}
	return pi
}
