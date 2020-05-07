#!/usr/bin/env python3

# Copyright 2020 Anapaya Systems

from pathlib import Path
import shutil
import sys
import tempfile

from plumbum import cli, local
from plumbum.cmd import docker


class Test(cli.Application):
    """
    Tests that the CS application logs to a file.
    """
    def main(self):
        tmpdir = tempfile.mkdtemp(prefix='service_filelog.')
        print(docker('image', 'load', '-i', './integration/service_filelog/cs.tar'))
        name = 'service_filelog_test'
        try:
            args = ['run', '--name', name, '-v', '{}:/share/logs'.format(tmpdir),
                    'bazel/integration/service_filelog:cs']
            print('docker', *args)
            print(docker(*args, retcode=1))
            logfile = Path('{}/cs.log'.format(tmpdir))
            if not logfile.is_file():
                print('{} is not a file'.format(logfile))
                sys.exit(1)
            if logfile.stat().st_size == 0:
                print('{} is empty'.format(logfile))
                sys.exit(1)
        finally:
            docker('logs', name)
            docker('rm', '-f', name)
            docker('rmi', 'bazel/integration/service_filelog:cs')
            shutil.rmtree(tmpdir, ignore_errors=True)

if __name__ == "__main__":
    Test.run()
