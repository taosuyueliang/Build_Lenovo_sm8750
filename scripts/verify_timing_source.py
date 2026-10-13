#!/usr/bin/env python3
"""Fail the build when SUSFS has replaced or disconnected the timing fix."""
import pathlib
import sys

kernel, ksu = map(pathlib.Path, sys.argv[1:])
feature = (ksu / 'kernel/feature/selinux_hide.c').read_text()
hooks = (kernel / 'security/selinux/hooks.c').read_text()
selinuxfs = (kernel / 'security/selinux/selinuxfs.c').read_text()
start = hooks.index('static int my_setprocattr(')
end = hooks.index('\n#endif', start)
hook = hooks[start:end]
for marker in ['ksu_security_context_to_sid_dual', 'PROCESS__SETCURRENT',
               'PROCESS__DYNTRANSITION', 'PROCESS__PTRACE', 'security_bounded_transition',
               'prepare_creds', 'commit_creds', 'abort_creds']:
    assert marker in hook, f'Missing live setprocattr path: {marker}'
assert hook.count('selinux_setprocattr(name, value, size)') == 1, 'Duplicate native conversion path'
assert 'LSM_HOOK_INIT(setprocattr, my_setprocattr)' in hooks
assert 'policydb_context_isvalid(orig_pol, orig_ctx)' in feature
assert 'security_context_to_sid(scontext2' not in feature, 'Old mutated-string sidtab shim is present'
assert 'return rc ? rc : orig_rc;' in feature
assert selinuxfs.count('security_context_to_sid_with_policy(backup_sepolicy,') == 3
assert 'susfs_set_batch_sid();' in (ksu / 'kernel/selinux/rules.c').read_text()
print('PASS: #3877 dual-policy converter + live SUSFS setprocattr + three SELinuxFS call sites; native permission checks retained')
