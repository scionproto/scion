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

const (
	ErrNoPublicAddress    = "no public address"
	ErrBindWithoutSvc     = "bind address without svc address"
	ErrBadISD             = "0 is not valid ISD"
	ErrBadAS              = "0 is not valid AS"
	ErrOverlappingAddress = "overlapping address"
	ErrNoValue            = "nil value"
	ErrZeroIP             = "zero address"
	ErrZeroPort           = "zero port"
	ErrNilAddress         = "nil address"
	ErrSvcNone            = "svc none"
	ErrNoPorts            = "no free ports"
)
