#!/usr/bin/python3
# -*- coding: utf-8 -*-

# This is exact replica of supervisord's entry point because I haven't
# found an intelligible way of creating a py_binary target that doesn't
# define its own entry point.

import re
import sys
from supervisor.supervisorctl import main
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())
