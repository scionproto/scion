#!/usr/bin/env python3

import sys
import subprocess

license_texts = {
    "#":"""
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
""",
    "//": """
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
""",
}

exceptions = [
    "go/lib/scrypto/cms",
    "go/lib/util/duration.go",
]

def is_ignored(f: str) -> bool:
    for e in exceptions:
        if e in f:
            return True
    return False

def main():
    not_ok = {}
    for f in sys.argv[1:]:
        if is_ignored(f):
            continue
        header = subprocess.check_output("head -15 %s" % f, stderr=subprocess.STDOUT, shell=True)
        lines = header.splitlines()
        if len(lines) < 1:
            not_ok[f] = "empty file"
            continue
        first_line = lines[0].decode("utf-8")
        # generated files don't matter
        if "generated" in header.decode("utf-8").lower():
            continue
        comment_marker = "//"
        if not first_line.startswith(comment_marker):
            comment_marker = "#"
            if not first_line.startswith(comment_marker):
                not_ok[f] = "no comment / unknown comment marker: %s" % first_line
                continue
        if license_texts[comment_marker] not in header.decode("utf-8"):
            not_ok[f] = "missing licence"
    for f, reason in not_ok.items():
        print("%s: %s" % (f, reason), file=sys.stderr)
    if len(not_ok) > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
