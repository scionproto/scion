// Copyright 2017 ETH Zürich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


// Creates a socket and connects to the SCION daemon specified by daemon_addr.
//
// On success, a sockfd file descriptor is returned. On error, a negative
// system error code is returned, namely those relating to socket and connect.
//
// @param daemon_addr The AF_UNIX address of the SCION daemon.
int daemon_connect(const char* daemon_addr);
