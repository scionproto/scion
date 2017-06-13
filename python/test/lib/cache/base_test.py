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
:mod:`lib_cache_base_test` --- lib.cache.base tests
=====================================================
"""
# Stdlib
from unittest.mock import call

# External packages
import nose.tools as ntools

# SCION
from lib.cache.base import Cache, CacheFullException
from test.testcommon import assert_these_calls, create_mock, create_mock_full


class TestCacheGet:
    """Unit tests for lib.cache.base.Cache.get"""

    def test(self, ):
        key = "key"
        default = "default"
        entry = "entry"
        cache = Cache()
        cache._cache[key] = entry
        cache._mk_key = create_mock_full(return_value=key)
        cache._expire_entry = create_mock_full(return_value=False)
        # Call
        ntools.eq_(cache.get(key, default=default), entry)
        # Tests
        assert_these_calls(cache._expire_entry, [call(entry)])

    def test_missing_entry(self):
        key = "key"
        default = "default"
        cache = Cache()
        # Call
        ntools.eq_(cache.get(key, default=default), default)

    def test_expired_entry(self):
        key = "key"
        default = "default"
        entry = "entry"
        cache = Cache()
        cache._cache[key] = entry
        cache._mk_key = create_mock_full(return_value=key)
        cache._expire_entry = create_mock_full(return_value=True)
        # Call
        ntools.eq_(cache.get(key, default=default), default)
        # Tests
        assert_these_calls(cache._expire_entry, [call(entry)])


class TestCacheAdd:
    """Unit tests for lib.cache.base.Cache.add"""
    def _create_entry(self, isd_as, if_id, epoch):
        entry_p = create_mock_full({"ifID": if_id, "epoch": epoch})
        entry = create_mock_full({"isd_as()": isd_as, "p": entry_p})
        return entry

    def test(self):
        key = "key"
        entry = "entry"
        cache = Cache()
        cache._mk_key = create_mock_full(return_value=key)
        cache._validate_entry = create_mock_full(return_value=True)
        cache.get = create_mock()
        cache.get.return_value = None
        # Call
        ntools.assert_true(cache.add(entry))
        # Tests
        ntools.eq_(cache._cache[key], entry)
        assert_these_calls(cache._validate_entry, [call(entry)])
        assert_these_calls(cache.get, [call(key)])

    def test_invalid_entry(self):
        entry = "entry"
        cache = Cache()
        cache._validate_entry = create_mock_full(return_value=False)
        # Call
        ntools.assert_false(cache.add(entry))
        assert_these_calls(cache._validate_entry, [call(entry)])

    def test_newer_entry_exists(self):
        key = "key"
        entry1 = "entry1"
        entry2 = "entry2"
        cache = Cache()
        cache._validate_entry = create_mock_full(return_value=True)
        cache._mk_key = create_mock_full(return_value=key)
        cache.get = create_mock_full(return_value=entry1)
        cache._is_newer = create_mock_full(return_value=False)
        cache._cache[key] = entry1
        # Call
        ntools.assert_false(cache.add(entry2))
        # Tests
        ntools.eq_(cache._cache[key], entry1)
        assert_these_calls(cache._validate_entry, [call(entry2)])
        assert_these_calls(cache._mk_key, [call(entry2)])
        assert_these_calls(cache.get, [call(key)])
        assert_these_calls(cache._is_newer, [call(entry2, entry1)])

    def test_older_entry_exists(self):
        key = "key"
        entry1 = "entry1"
        entry2 = "entry2"
        cache = Cache()
        cache._validate_entry = create_mock_full(return_value=True)
        cache._mk_key = create_mock_full(return_value=key)
        cache.get = create_mock_full(return_value=entry1)
        cache._is_newer = create_mock_full(return_value=True)
        cache._cache[key] = entry1
        # Call
        ntools.assert_true(cache.add(entry2))
        # Tests
        ntools.eq_(cache._cache[key], entry2)
        assert_these_calls(cache._validate_entry, [call(entry2)])
        assert_these_calls(cache._mk_key, [call(entry2)])
        assert_these_calls(cache.get, [call(key)])
        assert_these_calls(cache._is_newer, [call(entry2, entry1)])

    def test_with_free_up(self):
        key1 = "key1"
        key2 = "key2"
        entry1 = "entry1"
        entry2 = "entry2"

        def mk_key_side_effect(entry):
            return key1 if entry == entry1 else key2

        def validate_entry_side_effect(entry):
            return entry == entry2

        def expire_entry_side_effect(entry):
            if entry == entry1:
                del cache._cache[key1]
                return True
            return False

        cache = Cache(capacity=1)
        cache._cache[key1] = entry1
        cache._mk_key = create_mock_full(side_effect=mk_key_side_effect)
        cache._validate_entry = create_mock_full(side_effect=validate_entry_side_effect)
        cache._expire_entry = create_mock_full(side_effect=expire_entry_side_effect)
        cache.get = create_mock()
        cache.get.return_value = None
        # Call
        ntools.assert_true(cache.add(entry2))
        # Tests
        ntools.eq_(cache._cache[key2], entry2)
        ntools.assert_true(key1 not in cache._cache)
        assert_these_calls(cache._validate_entry, [call(entry2)])
        assert_these_calls(cache._mk_key, [call(entry2)])
        assert_these_calls(cache.get, [call(key2)])
        assert_these_calls(cache._expire_entry, [call(entry1)])

    def test_with_no_free_up(self):
        key1 = "key1"
        key2 = "key2"
        entry1 = "entry1"
        entry2 = "entry2"

        def mk_key_side_effect(entry):
            return key1 if entry == entry1 else key2

        cache = Cache(capacity=1)
        cache._cache[key1] = entry1
        cache._mk_key = create_mock_full(side_effect=mk_key_side_effect)
        cache._validate_entry = create_mock_full(return_value=True)
        cache._expire_entry = create_mock_full(return_value=False)
        cache.get = create_mock()
        cache.get.return_value = None
        # Call
        ntools.assert_raises(CacheFullException, cache.add, entry2)
        # Tests
        ntools.assert_true(key1 in cache._cache)
        ntools.assert_false(key2 in cache._cache)
        assert_these_calls(cache._validate_entry, [call(entry2)])
        assert_these_calls(cache._mk_key, [call(entry2)])
        assert_these_calls(cache.get, [call(key2)])
        assert_these_calls(cache._expire_entry, [call(entry1)])
