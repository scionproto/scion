#!/usr/bin/env python3
import json
import os
import tarfile
import datetime
import io
import sys
from git import Repo

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ad_management.common import SCION_ROOT, PACKAGE_DIR_PATH


def get_package_name(repo, commit):
    now = datetime.datetime.now()
    package_name = "scion_{}_{}.tar".format(commit.hexsha[:8],
                                            now.strftime("%d_%m_%y"))
    return package_name


def get_package_metadata(repo, commit):
    now = str(datetime.datetime.now())
    metadata = {'commit': commit.hexsha,
                'date': now,
                'with_config': False,
                }
    return metadata


def main():
    repo = Repo(SCION_ROOT)
    assert not repo.bare

    if len(sys.argv) > 1:
        commit_hash = repo.commit(sys.argv[1])
    else:
        commit_hash = repo.head.commit.hexsha

    commit = repo.commit(commit_hash)
    package_name = get_package_name(repo, commit)

    if not os.path.exists(PACKAGE_DIR_PATH):
        os.mkdir(PACKAGE_DIR_PATH)

    package_path = os.path.join(PACKAGE_DIR_PATH, package_name)

    with open(package_path, 'wb') as out_fh:
        repo.archive(out_fh, prefix='scion-package/')

    metadata = get_package_metadata(repo, commit)
    metadata_bytes = bytes(json.dumps(metadata, indent=2), 'utf-8')
    metadata_stream = io.BytesIO(metadata_bytes)

    # Append metadata
    with tarfile.open(package_path, 'a') as tar_fh:
        meta_tarinfo = tarfile.TarInfo('META')
        meta_tarinfo.size = len(metadata_bytes)
        tar_fh.addfile(meta_tarinfo, metadata_stream)

    print('Package created:   {}'.format(package_name))

if __name__ == '__main__':
    main()
