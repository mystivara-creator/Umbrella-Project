#!/usr/bin/env python3
"""Check host build prerequisites without downloading or modifying kernel sources."""
import shutil
import sys

required = ('git', 'make', 'python3', 'clang', 'ld.lld')
missing = [tool for tool in required if not shutil.which(tool)]
for tool in required:
    print(f'{tool}: {shutil.which(tool) or "MISSING"}')
if missing:
    print('Missing build prerequisites: ' + ', '.join(missing), file=sys.stderr)
    sys.exit(1)
print('Host prerequisites: PASS (does not establish kernel compatibility)')
