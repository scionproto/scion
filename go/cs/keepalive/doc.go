// Copyright 2019 Anapaya Systems
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

// Package keepalive implements tasks and handlers related IFID keepalives.
//
// Handler
//
// Call NewHandler to create an IFID keepalive handler that implements
// infra.Handler. The handler validates the keepalive and activates the
// interface it was received on. In case the interface changed its state to
// active, the handler immediately pushes in IfStateInfo update to all border
// routers and starts beaconing on the activated interface.
//
// Sender
//
// The sender periodically creates keepalive messages for all links.
package keepalive
