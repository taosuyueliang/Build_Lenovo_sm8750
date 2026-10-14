#!/usr/bin/env python3
"""Record build evidence. This does not claim device boot or detector success."""
import hashlib
import json
import pathlib
import re
import struct
import sys

kernel = pathlib.Path(sys.argv[1])
kpm = sys.argv[2].lower() == 'true'
out = kernel / 'out'
config = (out / '.config').read_text()
required = ['KSU', 'KSU_SUSFS', 'KSU_SUSFS_SUS_PATH', 'KSU_SUSFS_SUS_MOUNT',
            'KSU_SUSFS_SUS_KSTAT', 'KSU_SUSFS_SPOOF_UNAME', 'KSU_SUSFS_ENABLE_LOG',
            'KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS', 'KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG',
            'KSU_SUSFS_OPEN_REDIRECT', 'KSU_SUSFS_SUS_MAP', 'ARM64_4K_PAGES']
for name in required:
    assert f'CONFIG_{name}=y\n' in config, f'Effective config missing {name}'
assert ('CONFIG_KPM=y\n' in config) == kpm
symbols = (out / 'System.map').read_text()
for name in ['ksu_security_context_to_sid_dual', 'security_context_to_sid_with_policy', 'my_setprocattr',
             'ksu_shell_su_allowed_for_current', 'shell_su_adb_only_handler', 'cached_adbd_sid']:
    assert re.search(r'\b' + name + r'$', symbols, re.M), f'Linked symbol missing: {name}'
image = out / 'arch/arm64/boot/Image'
data = image.read_bytes()
assert data[56:60] == b'ARM\x64', 'Invalid arm64 Image magic'

def symbol_address(name):
    match = re.search(r'^([0-9a-f]+)\s+\w\s+' + re.escape(name) + r'$', symbols, re.M)
    assert match, f'Symbol address missing: {name}'
    return int(match.group(1), 16)


# ARM64 raw Image starts at _text. Check the emitted static key, not just a log.
shell_key_offset = symbol_address('ksu_shell_su_adb_only') - symbol_address('_text')
assert 0 <= shell_key_offset <= len(data) - 4
shell_key_initial = struct.unpack_from('<I', data, shell_key_offset)[0]
assert shell_key_initial == 1, 'Shell ADB restriction must be enabled in the built Image'
assert b'shell_su_adb_only\x00' in data
banners = sorted(set(x.decode('utf-8') for x in re.findall(rb'Linux version [^\x00\n]+', data)))
assert banners and all('6.6.118-android15-8-g350f378eb496-ab14943902-4k' in b and
    '(kleaf@build-host)' in b and '#1 SMP PREEMPT Thu Feb 26 02:40:50 UTC 2026' in b for b in banners)
print(json.dumps({'image_sha256':hashlib.sha256(data).hexdigest(), 'image_size':len(data),
    'linux_banners':banners, 'required_effective_config':required, 'kpm_enabled':kpm,
    'timing_linked_symbols':True, 'device_boot_test':'not_performed',
    'shell_su_adb_only': {'upstream_commit':'0a1f3ff71719fa2d6ec15f5568dac27fdb957fcc',
                        'feature_id':6, 'default_enabled':True,
                        'static_key_image_offset':shell_key_offset,
                        'static_key_initial_count':shell_key_initial,
                        'device_authorization_test':'not_performed'},
    'native_check_timing_test':'not_performed', 'stock_358_comparison':'requires_stock_boot'}, indent=2))
