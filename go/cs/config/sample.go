// Copyright 2020 Anapaya Systems
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

package config

const idSample = "cs-1"

const psSample = `
# The time after which segments for a destination are refetched. (default 5m)
query_interval = "5m"
# The path to the hidden paths configuration file. If the path is empty, hidden
# paths functionality is not enabled. If the path starts with http:// or
# https:// the configuration is fetched from the given URL. (default: "")
hidden_paths_cfg = ""
`

const caSample = `
# The maximum validity time of a renewed AS certificate the control server
# creates in a CA AS. The remaining validity of the locally available CA
# certificate must be larger than the here configured value at every given point
# in time. (i.e., ca.not_after - current_time >= max_as_validity) If that is not
# the case, certificate renewal is not possible until a new CA certificate is
# loaded that satisfies the condition. (default 3d)
max_as_validity = "3d"
`
