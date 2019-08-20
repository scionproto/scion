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
	"time"

	"github.com/scionproto/scion/go/lib/hostinfo"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest/graph"
)

// buildGAnswer returns the minimum-length paths from src to dst. If no path exists,
// the error code in the PathReply is set to ErrorNoPaths. If more than one
// minimum-length path exists, all minimum-length paths are returned.
//
// buildGAnswer does not guarantee to represent a consistent snapshot of the SCION
// network if the backing multigraph is modified while Paths is running.
func buildGAnswer(src, dst string, g *graph.Graph) *sciond.PathReply {
	paths := g.GetPaths(src, dst)
	var entries []sciond.PathReplyEntry
	for _, path := range paths {
		var pathInterfaces []sciond.PathInterface
		for _, ifid := range path {
			pathInterfaces = append(pathInterfaces,
				sciond.PathInterface{
					RawIsdas: g.GetParent(ifid).IAInt(),
					IfID:     ifid,
				},
			)
		}
		entries = append(entries,
			sciond.PathReplyEntry{
				Path: &sciond.FwdPathMeta{
					Interfaces: pathInterfaces,
					ExpTime:    util.TimeToSecs(time.Now().Add(spath.MaxTTL * time.Second)),
				},
				HostInfo: hostinfo.HostInfo{
					// TODO(scrye): leave nil for now since no tests use this
				},
			},
		)
	}
	if len(entries) == 0 {
		return &sciond.PathReply{
			ErrorCode: sciond.ErrorNoPaths,
			Entries:   entries,
		}
	}
	return &sciond.PathReply{
		ErrorCode: sciond.ErrorOk,
		Entries:   entries,
	}
}
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
