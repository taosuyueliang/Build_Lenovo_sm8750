#!/usr/bin/env python3
"""Repack the inspected TB322FC 358 boot, preserving its exact signed layout.

This deliberately targets two SHA256-identified inputs, not arbitrary boot images.
Requires the avbtool.py and public test key from the pinned signer repository.
No input image is modified. Device acceptance is not established by this script.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

STOCK_SHA = 'e7b3a286871788f0651ec6c62e7b086b88196968acc5462c42aba71136a1ef71'
TESTKEY_PUBLIC_SHA1 = '2597c218aae470a130f61162feaae70afd97f011'
PAGE = 4096
CERT_AREA = 16384


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['stock', 'kernel', 'avbtool', 'key', 'out']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--kernel-sha256', required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--build-run', required=True)
    args = parser.parse_args()
    require(re.fullmatch(r'[0-9a-f]{64}', args.kernel_sha256), 'Invalid kernel SHA256')
    require(re.fullmatch(r'[0-9a-f]{40}', args.source_commit), 'Invalid source commit')
    require(re.fullmatch(r'https://github.com/taosuyueliang/Build_Lenovo_sm8750/actions/runs/[0-9]+',
                         args.build_run), 'Unexpected build run URL')
    for name in ['stock', 'kernel', 'avbtool', 'key', 'out']:
        setattr(args, name, getattr(args, name).resolve())
    stock, kernel = args.stock.read_bytes(), args.kernel.read_bytes()
    require(sha(stock) == STOCK_SHA, 'Unexpected stock boot SHA256')
    require(sha(kernel) == args.kernel_sha256, 'Unexpected built kernel SHA256')
    require(stock[:8] == b'ANDROID!', 'Not an Android boot image')
    kernel_size, ramdisk_size, os_version, header_size = struct.unpack_from('<4I', stock, 8)
    header_version = struct.unpack_from('<I', stock, 40)[0]
    signature_size = struct.unpack_from('<I', stock, 1580)[0]
    require((header_version, header_size, ramdisk_size, signature_size) == (4, 1584, 0, 0),
            'Inspected boot v4 layout has changed')
    require(kernel[56:60] == b'ARM\x64', 'Not a raw ARM64 Image')

    spec = importlib.util.spec_from_file_location('avbtool', args.avbtool)
    avb = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(avb)
    engine = avb.Avb()
    key_blob = avb.RSAPublicKey(str(args.key)).encode()
    require(hashlib.sha1(key_blob).hexdigest() == TESTKEY_PUBLIC_SHA1, 'Unexpected test key')

    def parse_image(path):
        image = avb.ImageHandler(str(path), read_only=True)
        footer, header, descs, _ = engine._parse_image(image)
        offset = footer.vbmeta_offset if footer else 0
        data = Path(path).read_bytes()
        length = 256 + header.authentication_data_block_size + header.auxiliary_data_block_size
        blob = data[offset:offset + length]
        require(avb.verify_vbmeta_signature(header, blob), 'Invalid vbmeta signature: ' + str(path))
        return footer, header, descs, blob

    def public_key(header, blob):
        off = 256 + header.authentication_data_block_size + header.public_key_offset
        return blob[off:off + header.public_key_size]

    def details(header, descs, blob):
        hashes = [d for d in descs if isinstance(d, avb.AvbHashDescriptor)]
        props = [d for d in descs if isinstance(d, avb.AvbPropertyDescriptor)]
        require(len(hashes) == 1 and len(hashes) + len(props) == len(descs),
                'Unsupported descriptor set')
        d = hashes[0]
        require(header.public_key_metadata_size == 0 and d.flags in (0, 1),
                'Unsupported public key metadata or hash flags')
        alg, _ = avb.lookup_algorithm_by_type(header.algorithm_type)
        return {
            'algorithm': alg,
            'public_key_sha1': hashlib.sha1(public_key(header, blob)).hexdigest(),
            'rollback_index': header.rollback_index,
            'rollback_index_location': header.rollback_index_location,
            'flags': header.flags,
            'release_string': header.release_string,
            'required_libavb_version': [header.required_libavb_version_major,
                                       header.required_libavb_version_minor],
            'partition_name': d.partition_name,
            'hash_algorithm': d.hash_algorithm,
            'hash_flags': d.flags,
            'salt': d.salt.hex(),
            'hashed_image_size': d.image_size,
            'digest': d.digest.hex(),
            'properties': [[p.key, p.value.decode('utf-8')] for p in props],
        }

    def check_hash(descs, data):
        d, = [d for d in descs if isinstance(d, avb.AvbHashDescriptor)]
        require(d.image_size == len(data), 'Hash descriptor covers unexpected length')
        require(hashlib.new(d.hash_algorithm, d.salt + data).digest() == d.digest,
                'Hash descriptor mismatch')

    sf, sh, sd, sb = parse_image(args.stock)
    require(sf is not None and len(stock) == 100663296, 'Unexpected partition layout')
    check_hash(sd, stock[:sf.original_image_size])
    outer = details(sh, sd, sb)
    fingerprint = dict(outer['properties'])['com.android.build.boot.fingerprint']
    require('Lenovo/TB322FC_PRC/TB322FC:' in fingerprint and
            '/ZUXOS_1.5.10.358_260910_PRC:' in fingerprint, 'Unexpected firmware fingerprint')
    original_kernel = stock[PAGE:PAGE + kernel_size]
    banners = lambda data: sorted(set(x.decode('utf-8') for x in
                                      re.findall(rb'Linux version [^\x00\n]+', data)))
    require(banners(original_kernel) == banners(kernel), 'Full stock and candidate banners differ')
    old_prefix_len = PAGE + ((kernel_size + PAGE - 1) // PAGE) * PAGE
    require(sf.original_image_size - old_prefix_len == CERT_AREA, 'Unexpected GKI trailer length')
    require(not any(stock[PAGE + kernel_size:old_prefix_len]), 'Nonzero kernel alignment padding')

    # Read the actual kernel_size field. Magisk's DTB scan can split at
    # the kernel's built-in 72-byte empty FDT, exposing unrelated .data bytes.
    trailer = stock[old_prefix_len:sf.original_image_size]
    args.out.mkdir(parents=True, exist_ok=False)
    work = args.out / 'work'
    work.mkdir()
    templates = []
    offset = 0
    for index, data in enumerate([stock[:old_prefix_len], original_kernel]):
        require(trailer[offset:offset + 4] == b'AVB0', 'Missing GKI certificate')
        h = avb.AvbVBMetaHeader(trailer[offset:offset + 256])
        size = 256 + h.authentication_data_block_size + h.auxiliary_data_block_size
        path = work / f'original-gki-{index}.vbmeta'
        path.write_bytes(trailer[offset:offset + size])
        _, hh, dd, bb = parse_image(path)
        check_hash(dd, data)
        templates.append(details(hh, dd, bb))
        offset += size
    require(not any(trailer[offset:]), 'Unexpected bytes after GKI certificates')
    require([x['partition_name'] for x in templates] == ['boot', 'generic_kernel'],
            'Unexpected GKI certificate partitions')

    logs = []

    def command(words):
        result = subprocess.run([sys.executable, str(args.avbtool)] + words,
                                capture_output=True, text=True)
        logs.append({'args': words, 'returncode': result.returncode,
                     'stdout': result.stdout, 'stderr': result.stderr})
        require(result.returncode == 0, 'avbtool failed: ' + result.stderr)

    def signing_args(template, path):
        result = ['add_hash_footer', '--image', str(path),
                  '--partition_size', str(len(stock)),
                  '--partition_name', template['partition_name'],
                  '--hash_algorithm', template['hash_algorithm'],
                  '--algorithm', template['algorithm'], '--key', str(args.key),
                  '--salt', template['salt'],
                  '--rollback_index', str(template['rollback_index']),
                  '--rollback_index_location', str(template['rollback_index_location']),
                  '--flags', str(template['flags']),
                  '--internal_release_string', template['release_string']]
        if template['hash_flags'] == 1:
            result.append('--do_not_use_ab')
        for key, value in template['properties']:
            result += ['--prop', key + ':' + value]
        return result

    page = bytearray(stock[:PAGE])
    struct.pack_into('<I', page, 8, len(kernel))
    prefix = bytes(page) + kernel + b'\0' * (-len(kernel) % PAGE)
    new_certs = []
    cert_details = []
    unchanged = ['algorithm', 'rollback_index', 'rollback_index_location', 'flags',
                 'release_string', 'required_libavb_version', 'partition_name',
                 'hash_algorithm', 'hash_flags', 'salt', 'properties']
    for index, (template, data) in enumerate(zip(templates, [prefix, kernel])):
        source = work / ('boot.img' if index == 0 else 'generic_kernel.img')
        source.write_bytes(data)
        target = work / f'new-gki-{index}.img'
        command(signing_args(template, source) + ['--do_not_append_vbmeta_image',
                                                '--output_vbmeta_image', str(target)])
        _, h, d, b = parse_image(target)
        check_hash(d, data)
        require(public_key(h, b) == key_blob, 'GKI certificate key mismatch')
        info = details(h, d, b)
        for field in unchanged:
            require(info[field] == template[field], 'GKI metadata changed: ' + field)
        cert_details.append(info)
        new_certs.append(target.read_bytes())
        # Independent avbtool verification reads boot.img or generic_kernel.img
        # adjacent to the certificate when the descriptor partition differs.
        command(['verify_image', '--image', str(target), '--key', str(args.key)])

    new_trailer = b''.join(new_certs)
    require(len(new_trailer) <= CERT_AREA, 'GKI certificates exceed reserved area')
    new_trailer += b'\0' * (CERT_AREA - len(new_trailer))
    # avbtool resolves a nonempty 'boot' descriptor to an adjacent boot.img.
    result_path = args.out / 'boot.img'
    result_path.write_bytes(prefix + new_trailer)
    command(signing_args(outer, result_path))
    command(['verify_image', '--image', str(result_path), '--key', str(args.key)])
    final = result_path.read_bytes()
    nf, nh, nd, nb = parse_image(result_path)
    new_outer = details(nh, nd, nb)
    for field in unchanged:
        require(new_outer[field] == outer[field], 'Outer metadata changed: ' + field)
    require(public_key(nh, nb) == key_blob, 'Outer certificate key mismatch')
    require(len(final) == len(stock), 'Partition size changed')
    require(final[:8] == stock[:8] and final[12:PAGE] == stock[12:PAGE],
            'Boot header changed outside kernel_size')
    require(final[PAGE:PAGE + len(kernel)] == kernel, 'Embedded kernel differs from built artifact')
    require(final[len(prefix):nf.original_image_size] == new_trailer, 'Embedded GKI trailer changed')
    require((nf.version_major, nf.version_minor) == (sf.version_major, sf.version_minor),
            'AVB footer version changed')
    check_hash(nd, final[:nf.original_image_size])
    report = {
        'target': 'Lenovo TB322FC / ZUXOS 1.5.10.358',
        'source_commit': args.source_commit,
        'build_run': args.build_run,
        'signer_repository_commit': '0afc0203d9e28b37499f895bf1d4cf4e2f9c661a',
        'input_boot_sha256': STOCK_SHA,
        'kernel_sha256': args.kernel_sha256,
        'output_boot_sha256': sha(final),
        'output_boot_bytes': len(final),
        'output_filename': result_path.name,
        'avbtool_sha256': sha(args.avbtool.read_bytes()),
        'kernel_bytes': len(kernel),
        'stock_declared_kernel_bytes': kernel_size,
        'stock_declared_kernel_sha256': sha(original_kernel),
        'header_version': header_version,
        'header_size': header_size,
        'header_os_version': os_version,
        'header_signature_size': signature_size,
        'ramdisk_bytes': ramdisk_size,
        'boot_header_equal_except_kernel_size': True,
        'full_kernel_equal_to_build_artifact': True,
        'full_banner_equal_to_uploaded_boot': True,
        'linux_banners': banners(kernel),
        'gki_certificate_area_bytes': CERT_AREA,
        'gki_certificates_resigned_and_verified': True,
        'outer_avb_verified_with_expected_testkey': True,
        'preserved_avb_fields': unchanged,
        'input_avb': outer,
        'output_avb': new_outer,
        'input_gki_certificates': templates,
        'output_gki_certificates': cert_details,
        'device_boot_test': 'not_performed',
        'bootloader_accepts_testkey_on_this_device': 'user_reported_prior_success_not_independently_verified',
        'susfs_ui_runtime_test': 'not_performed',
        'shell_adb_only_device_test': 'not_performed',
        'native_check_timing_test': 'not_performed',
    }
    (args.out / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
    (work / 'avbtool-commands.json').write_text(json.dumps(logs, indent=2) + '\n')
    print(json.dumps({'output': str(result_path), 'sha256': sha(final),
                      'size': len(final), 'signature_and_layout_checks': 'PASS'}, indent=2))


if __name__ == '__main__':
    main()
