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

// Package mgmtapi implements the http status API of the router.
package mgmtapi

import (
	"encoding/json"
	"net/http"

	"github.com/scionproto/scion/pkg/addr"
	api "github.com/scionproto/scion/private/mgmtapi"
	"github.com/scionproto/scion/router/control"
)

// Server implements the http status API of the router.
type Server struct {
	Config    http.HandlerFunc
	Info      http.HandlerFunc
	LogLevel  http.HandlerFunc
	Dataplane control.ObservableDataplane
}

// GetConfig is an indirection to the http handler.
func (s *Server) GetConfig(w http.ResponseWriter, r *http.Request) {
	s.Config(w, r)
}

// GetInfo is an indirection to the http handler.
func (s *Server) GetInfo(w http.ResponseWriter, r *http.Request) {
	s.Info(w, r)
}

// GetLogLevel is an indirection to the http handler.
func (s *Server) GetLogLevel(w http.ResponseWriter, r *http.Request) {
	s.LogLevel(w, r)
}

// SetLogLevel is an indirection to the http handler.
func (s *Server) SetLogLevel(w http.ResponseWriter, r *http.Request) {
	s.LogLevel(w, r)
}

// GetInterfaces gets the interfaces and sibling interfaces of the router.
func (s *Server) GetInterfaces(w http.ResponseWriter, r *http.Request) {
	internalInterfaces, err := s.Dataplane.ListInternalInterfaces()
	if err != nil {
		ErrorResponse(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "error getting internal interface",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
	externalInterfaces, err := s.Dataplane.ListExternalInterfaces()
	if err != nil {
		ErrorResponse(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "error getting external interfaces",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
	siblingInterfaces, err := s.Dataplane.ListSiblingInterfaces()
	if err != nil {
		ErrorResponse(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "error getting sibling interfaces",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
	intfs := make([]Interface, 0, len(externalInterfaces))
	siblings := make([]SiblingInterface, 0, len(externalInterfaces))

	findInternalInterface := func(ia addr.IA) string {
		for _, intf := range internalInterfaces {
			if intf.IA.Equal(ia) {
				return intf.Addr.String()
			}
		}
		return "undefined"
	}
	for _, intf := range externalInterfaces {
		newInterface := Interface{
			Bfd: BFD{
				DesiredMinimumTxInterval: intf.Link.BFD.DesiredMinTxInterval.String(),
				DetectionMultiplier:      int(intf.Link.BFD.DetectMult),
				Enabled:                  !*(intf.Link.BFD.Disable),
				RequiredMinimumReceive:   intf.Link.BFD.RequiredMinRxInterval.String(),
			},
			InterfaceId:       int(intf.IfID), // nolint - name from published API.
			InternalInterface: findInternalInterface(intf.Link.Local.IA),
			Neighbor: InterfaceNeighbor{
				Address: intf.Link.Remote.Addr.String(),
				IsdAs:   intf.Link.Remote.IA.String(),
			},
			Relationship: LinkRelationship(intf.Link.LinkTo.String()),
			ScionMtu:     intf.Link.MTU,
			State:        LinkState(intf.State),
		}

		intfs = append(intfs, newInterface)
	}

	for _, intf := range siblingInterfaces {
		siblingInterface := SiblingInterface{
			InterfaceId:       int(intf.IfID), // nolint - name from published API.
			InternalInterface: intf.InternalInterface.String(),
			Neighbor: SiblingNeighbor{
				IsdAs: intf.NeighborIA.String(),
			},
			Relationship: LinkRelationship(intf.Relationship.String()),
			ScionMtu:     intf.MTU,
			State:        LinkState(intf.State),
		}

		siblings = append(siblings, siblingInterface)
	}

	rep := InterfacesResponse{
		Interfaces:        &intfs,
		SiblingInterfaces: &siblings,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "    ")
	if err := enc.Encode(rep); err != nil {
		ErrorResponse(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "unable to marshal response",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
}

// Error creates an detailed error response.
func ErrorResponse(w http.ResponseWriter, p Problem) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "    ")
	// no point in catching error here, there is nothing we can do about it anymore.
	_ = enc.Encode(p)
}
