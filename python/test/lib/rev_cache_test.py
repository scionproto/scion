# Copyright 2017 ETH Zurich
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
:mod:`lib_rev_cache_test` --- lib.rev_cache tests
=====================================================
"""
# Stdlib
import time
from unittest.mock import call, patch

# External packages
import nose.tools as ntools

# SCION
from lib.rev_cache import RevCache
from lib.types import LinkType
from test.testcommon import assert_these_calls, create_mock, create_mock_full


class TestRevCacheGet:
    """Unit tests for lib.rev_cache.RevCache.get"""
    def test(self):
        key = ("1-1", 1)
        default = "default"
        rev_info = "rev_info"
        rev_cache = RevCache()
        rev_cache._cache[key] = rev_info
        rev_cache._validate_entry = create_mock_full(return_value=True)
        # Call
        ntools.eq_(rev_cache.get(key, default=default), rev_info)
        # Tests
        assert_these_calls(rev_cache._validate_entry, [call(rev_info)])

    def test_missing_entry(self):
        key = ("1-1", 1)
        default = "default"
        rev_cache = RevCache()
        # Call
        ntools.eq_(rev_cache.get(key, default=default), default)

    def test_expired_entry(self):
        key = ("1-1", 1)
        default = "default"
        rev_info = "rev_info"
        rev_cache = RevCache()
        rev_cache._cache[key] = rev_info
        rev_cache._validate_entry = create_mock_full(return_value=False)
        # Call
        ntools.eq_(rev_cache.get(key, default=default), default)
        # Tests
        assert_these_calls(rev_cache._validate_entry, [call(rev_info)])


class TestRevCacheAdd:
    """Unit tests for lib.rev_cache.RevCache.add"""
    def _create_rev_info(self, isd_as, if_id, link_type=LinkType.CORE,
                         timestamp=int(time.time()), revTTL=10):
        rev_info_p = create_mock_full({"ifID": if_id, "link_type": link_type,
                                       "timestamp": timestamp, "revTTL": revTTL})
        now = int(time.time())
        active = (timestamp <= now + 1) and now < (timestamp + revTTL)
        rev_info = create_mock_full({"isd_as()": isd_as,
                                     "active()": active, "p": rev_info_p})

        return rev_info

    def test(self):
        key = ("1-1", 1)
        rev_info = self._create_rev_info(key[0], key[1])
        rev_cache = RevCache()
        rev_cache.get = create_mock()
        rev_cache.get.return_value = None
        # Call
        ntools.assert_true(rev_cache.add(rev_info))
        # Tests
        ntools.eq_(rev_cache._cache[key], rev_info)
        assert_these_calls(rev_cache.get, [call(key)])
        assert_these_calls(rev_info.active, [call()])

    def test_invalid_entry(self):
        rev_info = self._create_rev_info("1-1", 1, timestamp=int(time.time())-20)
        rev_cache = RevCache()
        # Call
        ntools.assert_false(rev_cache.add(rev_info))
        assert_these_calls(rev_info.active, [call()])

    def test_same_entry_exists(self):
        key = ("1-1", 1)
        now = int(time.time())
        rev_info1 = self._create_rev_info(key[0], key[1], timestamp=now)
        rev_info2 = self._create_rev_info(key[0], key[1], timestamp=now)
        rev_cache = RevCache()
        rev_cache.get = create_mock_full(return_value=rev_info1)
        rev_cache._cache[key] = rev_info1
        # Call
        ntools.assert_false(rev_cache.add(rev_info2))
        # Tests
        ntools.eq_(rev_cache._cache[key], rev_info1)
        assert_these_calls(rev_info2.active, [call()])
        assert_these_calls(rev_cache.get, [call(key)])

    def test_newer_entry_exists(self):
        key = ("1-1", 1)
        now = int(time.time())
        rev_info1 = self._create_rev_info(key[0], key[1], timestamp=now + 1)
        rev_info2 = self._create_rev_info(key[0], key[1], timestamp=now)
        rev_cache = RevCache()
        rev_cache.get = create_mock_full(return_value=rev_info1)
        rev_cache._cache[key] = rev_info1
        # Call
        ntools.assert_false(rev_cache.add(rev_info2))
        # Tests
        ntools.eq_(rev_cache._cache[key], rev_info1)
        assert_these_calls(rev_info2.active, [call()])
        assert_these_calls(rev_cache.get, [call(key)])

    def test_older_entry_exists(self):
        key = ("1-1", 1)
        now = int(time.time())
        rev_info1 = self._create_rev_info(key[0], key[1], timestamp=now)
        rev_info2 = self._create_rev_info(key[0], key[1], timestamp=now +1)
        rev_cache = RevCache()
        rev_cache.get = create_mock_full(return_value=rev_info1)
        rev_cache._cache[key] = rev_info1
        # Call
        ntools.assert_true(rev_cache.add(rev_info2))
        # Tests
        ntools.eq_(rev_cache._cache[key], rev_info2)
        assert_these_calls(rev_info2.active, [call()])
        assert_these_calls(rev_cache.get, [call(key)])

    def test_with_free_up(self):
        key1 = ("1-1", 1)
        key2 = ("1-2", 1)
        now = int(time.time())
        rev_info1 = self._create_rev_info(key1[0], key1[1], timestamp=now)
        rev_info2 = self._create_rev_info(key2[0], key2[1], timestamp=now + 1)

        def validate_entry_side_effect(rev_info):
            del rev_cache._cache[(rev_info.isd_as(), rev_info.p.ifID)]
            return False

        rev_cache = RevCache(capacity=1)
        rev_cache._cache[key1] = rev_info1
        rev_cache._validate_entry = create_mock()
        rev_cache._validate_entry.side_effect = validate_entry_side_effect
        rev_cache.get = create_mock()
        rev_cache.get.return_value = None
        # Call
        ntools.assert_true(rev_cache.add(rev_info2))
        # Tests
        ntools.eq_(rev_cache._cache[key2], rev_info2)
        ntools.assert_true(key1 not in rev_cache._cache)
        assert_these_calls(rev_info2.active, [call()])
        assert_these_calls(rev_cache.get, [call(key2)])

    def test_with_no_free_up(self):
        key1 = ("1-1", 1)
        key2 = ("1-2", 1)
        now = int(time.time())
        rev_info1 = self._create_rev_info(key1[0], key1[1], timestamp=now)
        rev_info2 = self._create_rev_info(key2[0], key2[1], timestamp=now + 1)
        rev_cache = RevCache(capacity=1)
        rev_cache._cache[key1] = rev_info1
        rev_cache._validate_entry = create_mock_full(return_value=True)
        rev_cache.get = create_mock()
        rev_cache.get.return_value = None
        # Call
        ntools.assert_false(rev_cache.add(rev_info2))
        # Tests
        ntools.assert_true(key1 in rev_cache._cache)
        assert_these_calls(rev_info2.active, [call()])
        assert_these_calls(rev_cache.get, [call(key2)])
