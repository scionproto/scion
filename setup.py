#!/usr/bin/env python3

from distutils.core import setup
from setuptools import find_packages

packages = find_packages()
print('Packages found: ' + str(packages))

setup(name='scion',
      version='0.1.0',
      description='SCION package',
      url='https://github.com/netsec-ethz/scion',
      author='SCION',
      author_email='scion@scion.net',
      packages=packages,
     )
