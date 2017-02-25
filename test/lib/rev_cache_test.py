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
from unittest.mock import patch

# External packages
import nose.tools as ntools

# SCION
from lib.rev_cache import RevCache
from test.testcommon import create_mock, create_mock_full


class TestRevCacheGet:
    """Unit tests for lib.rev_cache.RevCache.get"""
    @patch("lib.rev_cache.RevCache._validate_entry", new_callable=create_mock)
    def test(self, validate_entry):
        key = ("1-1", 1)
        default = "default"
        rev_info = "rev_info"
        rev_cache = RevCache()
        rev_cache._cache[key] = rev_info
        validate_entry.return_value = True
        # Test
        ntools.eq_(rev_cache.get(key, default=default), rev_info)

    def test_missing_entry(self):
        key = ("1-1", 1)
        default = "default"
        rev_cache = RevCache()
        # Test
        ntools.eq_(rev_cache.get(key, default=default), default)

    @patch("lib.rev_cache.RevCache._validate_entry", new_callable=create_mock)
    def test_expired_entry(self, validate_entry):
        key = ("1-1", 1)
        default = "default"
        rev_info = "rev_info"
        rev_cache = RevCache()
        rev_cache._cache[key] = rev_info
        validate_entry.return_value = False
        # Test
        ntools.eq_(rev_cache.get(key, default=default), default)


class TestRevCacheAdd:
    """Unit tests for lib.rev_cache.RevCache.add"""
    def _create_rev_info(self, isd_as, if_id, epoch):
        rev_info_p = create_mock_full({"ifID": if_id, "epoch": epoch})
        rev_info = create_mock_full({"isd_as()": isd_as, "p": rev_info_p})
        return rev_info

    @patch("lib.crypto.hash_tree.ConnectedHashTree.verify_epoch",
           new_callable=create_mock)
    @patch("lib.rev_cache.RevCache._validate_entry", new_callable=create_mock)
    @patch("lib.rev_cache.RevCache.__getitem__", new_callable=create_mock)
    def test(self, get_item, validate_entry, verify_epoch):
        rev_info = self._create_rev_info("1-1", 1, 2)
        get_item.return_value = None
        verify_epoch.return_value = True
        validate_entry.return_value = True
        rev_cache = RevCache()
        # Call
        ret = rev_cache.add(rev_info)
        # Tests
        ntools.assert_true(ret)
        ntools.eq_(rev_cache._cache[("1-1", 1)], rev_info)

    @patch("lib.crypto.hash_tree.ConnectedHashTree.verify_epoch",
           new_callable=create_mock)
    def test_invalid_entry(self, verify_epoch):
        rev_info = self._create_rev_info("1-1", 1, 2)
        verify_epoch.return_value = False
        rev_cache = RevCache()
        # Tests
        ntools.assert_false(rev_cache.add(rev_info))

    @patch("lib.crypto.hash_tree.ConnectedHashTree.verify_epoch",
           new_callable=create_mock)
    @patch("lib.rev_cache.RevCache.__getitem__", new_callable=create_mock)
    def test_same_entry_exists(self, get_item, verify_epoch):
        rev_info1 = self._create_rev_info("1-1", 1, 1)
        rev_info2 = self._create_rev_info("1-1", 1, 1)
        get_item.return_value = rev_info1
        verify_epoch.return_value = True
        rev_cache = RevCache()
        rev_cache._cache[("1-1", 1)] = rev_info1
        # Call
        ret = rev_cache.add(rev_info2)
        # Tests
        ntools.assert_false(ret)
        ntools.eq_(rev_cache._cache[("1-1", 1)], rev_info1)

    @patch("lib.crypto.hash_tree.ConnectedHashTree.verify_epoch",
           new_callable=create_mock)
    @patch("lib.rev_cache.RevCache._validate_entry", new_callable=create_mock)
    @patch("lib.rev_cache.RevCache.__getitem__", new_callable=create_mock)
    def test_with_free_up(self, get_item, validate_entry, verify_epoch):
        rev_info1 = self._create_rev_info("1-1", 1, 1)
        rev_info2 = self._create_rev_info("1-2", 1, 2)
        get_item.return_value = None
        verify_epoch.return_value = True

        def validate_entry_side_effect(rev_info):
            del rev_cache._cache[(rev_info.isd_as(), rev_info.p.ifID)]
            return False

        validate_entry.side_effect = validate_entry_side_effect
        rev_cache = RevCache(capacity=1)
        rev_cache._cache[("1-1", 1)] = rev_info1
        # Call
        ret = rev_cache.add(rev_info2)
        # Tests
        ntools.assert_true(ret)
        ntools.eq_(rev_cache._cache[("1-2", 1)], rev_info2)
        ntools.assert_true(("1-1", 1) not in rev_cache._cache)

    @patch("lib.crypto.hash_tree.ConnectedHashTree.verify_epoch",
           new_callable=create_mock)
    @patch("lib.rev_cache.RevCache._validate_entry", new_callable=create_mock)
    @patch("lib.rev_cache.RevCache.__getitem__", new_callable=create_mock)
    def test_with_no_free_up(self, get_item, validate_entry, verify_epoch):
        rev_info1 = self._create_rev_info("1-1", 1, 1)
        rev_info2 = self._create_rev_info("1-2", 1, 2)
        get_item.return_value = None
        verify_epoch.return_value = True
        validate_entry.return_value = True
        rev_cache = RevCache(capacity=1)
        rev_cache._cache[("1-1", 1)] = rev_info1
        # Call
        ret = rev_cache.add(rev_info2)
        # Tests
        ntools.assert_false(ret)
        ntools.assert_true(("1-1", 1) in rev_cache._cache)
