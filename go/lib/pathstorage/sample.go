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

package pathstorage

const pathDbSample = `
# The type of pathdb backend.
Backend = "sqlite"

# Path to the path database.
Connection = "/var/lib/scion/pathdb/%s.path.db"
`

const revSample = `
# The type of RevCache backend.
Backend = "mem"
`
