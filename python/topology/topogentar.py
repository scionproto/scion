#!/usr/bin/env python3

# Copyright 2020 Anapaya Systems

import os
import shutil
import tempfile

from plumbum import cli, local
from plumbum.cmd import cp, sed, tar


class Gen(cli.Application):
    """
    Generates a tar package for the given topology file. The created tar
    contains the output of a topogen run. This is needed so that the bazel test
    can consume this tar, in bazel you can't specify an unknown amount of files
    as output, therefore a tar is used to pack everything up.
    """
    topogen_bin = './python/generator.py'
    cryptolib = './scripts/cryptoplayground/crypto_lib.sh'
    scion_pki_bin = './bin/scion-pki'
    topo = "default.topo"
    outfile = 'gen.tar'
    params = ''

    @cli.switch('topogen_bin', str, help='topogen binary path (default ./python/generator.py)')
    def set_topogen_bin(self, topogen_bin: str):
        self.topogen_bin = topogen_bin

    @cli.switch('scion_pki', str, help='scion-pki binary path (default ./bin/scion-pki)')
    def set_scion_pki(self, scion_pki: str):
        self.scion_pki_bin = scion_pki

    @cli.switch('topo', str, help='Input topo file (default default.topo)')
    def set_topo(self, topo: str):
        self.topo = topo

    @cli.switch('out', str, help='Output tar file (default out.tar)')
    def out(self, outfile: str):
        self.outfile = outfile

    @cli.switch('params', str, help='Additional arguments to pass to topogen')
    def set_params(self, params: str):
        self.params = params

    def main(self):
        tmpdir = local.path(tempfile.mkdtemp(prefix='topogen.'))
        try:
            scion_pki = local.path(self.scion_pki_bin)
            topogen = local[self.topogen_bin]
            local.env.path.insert(0, scion_pki.parent)
            # bazel only creates a symlink to the crypto_lib,
            # we copy it to tmp so that it works with docker.
            cp('-L', local.path('./scripts/cryptoplayground/crypto_lib.sh'), tmpdir)
            topogen_args = ['-o', tmpdir / 'gen', '-c', self.topo]
            if self.params != '':
                topogen_args += self.params.split()
            with local.env(CRYPTOLIB=tmpdir / 'crypto_lib.sh'):
                print('Running topogen with following arguments: ' + ' '.join(topogen_args))
                print(topogen(*topogen_args))
            # Remove the explicit scion root dir, so that tests can adapt this to wherever they
            # unpack the tar.
            sed('-i', 's@%s@$SCIONROOT@g' % local.path('.'), tmpdir / 'gen' / 'scion-dc.yml')
            sed('-i', 's@%s@$SCIONROOT@g' % tmpdir, tmpdir / 'gen' / 'scion-dc.yml')
            for support_dir in ['logs', 'gen-cache', 'gen-data', 'traces']:
                os.mkdir(tmpdir / support_dir)
            tar('-C', tmpdir, '-cf', self.outfile, '.')
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    Gen.run()
