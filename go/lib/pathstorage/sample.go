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
backend = "sqlite"

# Path to the path database.
connection = "/var/lib/scion/pathdb/%s.path.db"

# The maximum number of open connections to the database. In case of the
# empty string, the limit is not set and uses the go default. (default "")
max_open_conns = ""

# The maximum number of idle connections to the database. In case of the
# empty string, the limit is not set and uses the go default. (default "")
max_idle_conns = ""
`

const revSample = `
# The type of RevCache backend.
backend = "mem"

# The maximum number of open connections to the database. In case of the
# empty string, the limit is not set and uses the go default. (default "")
max_open_conns = ""

# The maximum number of idle connections to the database. In case of the
# empty string, the limit is not set and uses the go default. (default "")
max_idle_conns = ""
`
