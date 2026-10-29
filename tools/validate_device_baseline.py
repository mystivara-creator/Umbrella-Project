#!/usr/bin/env python3
"""Validate captured device facts. Does not validate a kernel build or flash safety."""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
PATH = ROOT / 'config/devices/kunzite-global.json'

def main():
    d = json.loads(PATH.read_text(encoding='utf-8'))
    required = ('model', 'codename', 'board', 'mod_device', 'hyperos',
                'kernel_release', 'architecture', 'kmi_family', 'kmi_generation',
                'page_size_bytes', 'source_status', 'flash_status')
    for key in required:
        if key not in d:
            raise ValueError(f'missing field: {key}')
    match = re.fullmatch(r'(\d+\.\d+\.\d+)-android(\d+)-(\d+)-g[0-9a-f]+-ab\d+-(\d+)k', d['kernel_release'])
    if not match:
        raise ValueError('unexpected kernel release format')
    version, android, generation, pages_k = match.groups()
    if d['kmi_family'] != f'android{android}-{version.rsplit(".", 1)[0]}':
        raise ValueError('KMI family mismatch')
    if int(generation) != d['kmi_generation']:
        raise ValueError('KMI generation mismatch')
    if int(pages_k) * 1024 != d['page_size_bytes']:
        raise ValueError('page size mismatch')
    if d['source_status'] != 'unverified' or d['flash_status'] != 'not_approved':
        raise ValueError('this checkpoint must not claim verified source or flash readiness')
    print('Umbrella v0.2.0 device baseline: PASS (source/build/flash NOT verified)')

if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        sys.exit(1)
