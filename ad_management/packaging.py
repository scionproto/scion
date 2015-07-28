#!/usr/bin/env python3
# Copyright 2015 ETH Zurich
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
:mod:`packaging` --- packaging module
======================================================
"""

# Stdlib
import datetime
import io
import json
import os
import sys
import tarfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# External packages
from git import Repo

# SCION
from ad_management.common import PACKAGE_DIR_PATH
from lib.defines import PROJECT_ROOT

DEFAULT_EXTENSION = '.tar'


def get_package_name(commit):
    """
    Generate a package name from a commit hash and date.
    """
    now = datetime.datetime.now()
    package_name = "scion_{}_{}{}".format(commit.hexsha[:8],
                                          now.strftime("%d_%m_%y"),
                                          DEFAULT_EXTENSION)
    return package_name


def get_package_metadata(commit):
    """
    Get a dict of package metadata.
    """
    now = datetime.datetime.now()
    metadata = {'commit': commit.hexsha,
                'date': str(now),
                }
    return metadata


def prepare_package(out_dir=PACKAGE_DIR_PATH, package_name=None,
                    config_paths=None, commit_hash=None):
    """
    Create a package from the provided revision.

    :param out_dir: output directory
    :type out_dir: str
    :param package_name: output package name
    :type package_name: str
    :param config_paths: paths to configuration files that will be included in
                         the package
    :type config_paths: list
    :param commit_hash: revision which will be packaged
    :type commit_hash: str
    :return: path to the generated package
    :rtype: str
    """
    repo = Repo(PROJECT_ROOT)
    assert not repo.bare

    if commit_hash is None:
        commit_hash = repo.head.commit.hexsha

    commit = repo.commit(commit_hash)

    if package_name is None:
        package_name = get_package_name(commit)

    if not package_name.endswith(DEFAULT_EXTENSION):
        package_name += DEFAULT_EXTENSION

    if not os.path.isdir(out_dir):
        os.mkdir(out_dir)

    package_path = os.path.join(out_dir, package_name)

    package_prefix = 'scion-package/'
    with open(package_path, 'wb') as out_fh:
        repo.archive(out_fh, prefix=package_prefix, worktree_attributes=True,
                     treeish=commit)

    # Append configs
    if config_paths is not None:
        if isinstance(config_paths, str):
            config_paths = [config_paths]
        with tarfile.open(package_path, 'a') as tar_fh:
            for path in config_paths:
                assert os.path.isdir(path)
                dirname = os.path.basename(path)
                arcname = os.path.join(package_prefix, 'topology', dirname)
                tar_fh.add(path, arcname)

    # Append metadata
    metadata = get_package_metadata(commit)
    metadata['with_config'] = (config_paths is not None)
    metadata_bytes = bytes(json.dumps(metadata, indent=2), 'utf-8')
    metadata_stream = io.BytesIO(metadata_bytes)
    with tarfile.open(package_path, 'a') as tar_fh:
        meta_tarinfo = tarfile.TarInfo('META')
        meta_tarinfo.size = len(metadata_bytes)
        tar_fh.addfile(meta_tarinfo, metadata_stream)

    print('Package created:   {}'.format(package_name))
    return package_path


if __name__ == '__main__':
    if len(sys.argv) > 1:
        commit_hash = sys.argv[1]
    else:
        commit_hash = None
    prepare_package(commit_hash=commit_hash)
