"""
defines.py

Copyright 2015 ETH Zurich

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

"""
:mod:`defines` --- Constants
=============================

Contains constant definitions used throughout the codebase.

"""

MAX_SEGMENT_TTL = 24 * 60 * 60  # Max TTL of a PathSegment in realtime seconds.
EXP_TIME_UNIT = MAX_SEGMENT_TTL / 2 ** 8  # Time unit for HOF expiration.