// Copyright 2021 Anapaya Systems
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

package snet

import (
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path"
)

type DefaultReplyPather struct{}

func (DefaultReplyPather) ReplyPath(rpath RawPath) (DataplanePath, error) {
	p, err := path.NewPath(rpath.PathType)
	if err != nil {
		return nil, serrors.WrapStr("creating path", err, "type", rpath.PathType)
	}
	if err := p.DecodeFromBytes(rpath.Raw); err != nil {
		return nil, serrors.WrapStr("decoding path", err)
	}
	reversed, err := p.Reverse()
	if err != nil {
		return nil, serrors.WrapStr("reversing path", err)
	}
	return RawReplyPath{
		Path: reversed,
	}, nil
}

type RawReplyPath struct {
	Path path.Path
}

func (p RawReplyPath) SetPath(s *slayers.SCION) error {
	s.Path, s.PathType = p.Path, p.Path.Type()
	return nil
}
