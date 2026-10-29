#!/usr/bin/env python3
"""Fail closed until the device-specific source provenance is recorded."""
import json
from pathlib import Path

p = Path(__file__).resolve().parents[1] / 'config/sources/kernel-source.json'
d = json.loads(p.read_text())
assert d['device'] == 'kunzite_global'
assert d['kernel_release_observed'].startswith('6.6.118-android15-8-')
assert d['source_status'] in ('unverified', 'verified')
if d['source_status'] == 'verified':
    for key in ('repository', 'commit', 'defconfig', 'toolchain'):
        assert isinstance(d[key], str) and d[key].strip(), f'Missing {key}'
    print('Source metadata: VERIFIED BY DECLARATION (technical compatibility still requires testing)')
else:
    print('Source metadata: PENDING — source and compatibility not verified')
