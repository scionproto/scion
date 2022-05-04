# Copyright 2014 ETH Zurich
#
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
"""
:mod:`util` --- SCION utilities
===============================
"""
import pathlib


def write_file(file_path, text):
    """
    Write some text into file, creating its directory as needed.
    :param str file_path: the path to the file.
    :param str text: the file content.
    """
    # ":" is an illegal filename char on both windows and OSX, so disallow it globally to prevent
    # incompatibility.
    assert ":" not in file_path, file_path

    pathlib.Path(file_path).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(file_path).write_text(text)
