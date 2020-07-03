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

package log

const loggingFileSample = `
# Location of the logging file. If not specified, logging to file is disabled.
path = "/var/log/scion/%s.log"

# File logging level. (trace|debug|info|warn|error|crit) (default debug)
level = "debug"

# Max size of log file in MiB. (default 50)
size = 50

# Max age of log file in days. (default 7)
max_age = 7

# Maximum number of log files to retain. (default 10)
max_backups = 10

# How frequently to flush to the log file, in seconds. If 0, all messages
# are immediately flushed. If negative, messages are never flushed
# automatically. (default 5)
flush_interval = 5

# Logging fromat (human|json) (default human)
format = "human"
`

const loggingConsoleSample = `
# Console logging level (trace|debug|info|warn|error|crit) (default crit)
level = "crit"

# Logging fromat (human|json) (default human)
format = "human"
`
