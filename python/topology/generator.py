#!/usr/bin/python3
# Copyright 2014 ETH Zurich
# Copyright 2018 ETH Zurich, Anapaya Systems
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
:mod:`generator` --- SCION topology generator
=============================================
"""
# SCION
from topology.config import (
    ConfigGenerator,
    ConfigGenArgs,
)


def main():
    """
    Main function.
    """
    parser = ConfigGenArgs.create_parser()
    args = ConfigGenArgs(parser.parse_args())
    confgen = ConfigGenerator(args)
    confgen.generate_all()


if __name__ == "__main__":
    main()
