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

package registration

import "github.com/scionproto/scion/go/lib/common"

const (
	ErrNoPublicAddress    common.ErrMsg = "no public address"
	ErrBindWithoutSvc     common.ErrMsg = "bind address without svc address"
	ErrOverlappingAddress common.ErrMsg = "overlapping address"
	ErrNoValue            common.ErrMsg = "nil value"
	ErrZeroIP             common.ErrMsg = "zero address"
	ErrZeroPort           common.ErrMsg = "zero port"
	ErrNilAddress         common.ErrMsg = "nil address"
	ErrSvcNone            common.ErrMsg = "svc none"
	ErrNoPorts            common.ErrMsg = "no free ports"
)
