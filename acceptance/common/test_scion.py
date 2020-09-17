# Copyright 2019 Anapaya Systems
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

import os
import shutil
import tempfile
import unittest
from typing import Any, Dict, List

from plumbum import local

from acceptance.common.scion import (
    merge_dict,
    path_to_dict,
    svc_names_from_path,
)


class MergeDictTestCase(unittest.TestCase):

    def test_add_entry(self):
        actual = self._orig()
        merge_dict({'trustdb': 'insert'}, actual)
        expected = self._orig()
        expected['trustdb'] = 'insert'
        self.assertEqual(actual, expected, "trustdb not inserted")

    def test_replace_leaf_entry(self):
        actual = self._orig()
        merge_dict(path_to_dict('log.file.level', 'crit'), actual)
        expected = self._orig()
        expected['log']['file']['level'] = 'crit'
        self.assertEqual(actual, expected, "level not overwritten")

    def test_replace_dict(self):
        actual = self._orig()
        merge_dict(path_to_dict('log.file', 'disable'), actual)
        expected = self._orig()
        expected['log']['file'] = 'disable'
        self.assertEqual(actual, expected, "file dict not overwritten")

    @staticmethod
    def _orig() -> Dict[str, Any]:
        return {
            'log': {
                'file': {
                    'path': '/var/log/scion/bs.log',
                    'level': 'info',
                },
                'console': False,
            }
        }


class PathToDictTestCase(unittest.TestCase):

    def test_path_to_dict(self):
        d = path_to_dict('a.b.c', 'd')
        self.assertEqual(d, {'a': {'b': {'c': 'd'}}}, 'wrong dictionary')


class SvcNameFromPathTestCase(unittest.TestCase):

    def setUp(self):
        self.dir = local.path(tempfile.mkdtemp())
        files = ['AS1/bs1.toml', 'AS1/topology.json', 'AS2/bs2.toml', 'AS2/cs2.toml']
        self._touch_files(files)

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_directory(self):
        path = local.path(self.dir) / 'AS2'
        actual = svc_names_from_path([path])
        self.assertEqual(set(actual), {'bs2', 'cs2'}, 'wrong service names')

    def test_directories(self):
        path = local.path(self.dir) // 'AS*'
        actual = svc_names_from_path(path)
        self.assertEqual(set(actual), {'bs1', 'bs2', 'cs2'}, 'wrong service names')

    def _touch_files(self, names: List[str]):
        for name in names:
            file = self.dir / name
            file.dirname.mkdir()
            with open(os.path.join(self.dir, name), 'a'):
                pass
