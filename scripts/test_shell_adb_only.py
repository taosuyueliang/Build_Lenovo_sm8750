#!/usr/bin/env python3
"""Exercise actual #3882 C code using task/SELinux/allowlist stubs.

Checks authorization decisions and feature registration, not kernel scheduling,
RCU concurrency, Android SELinux policy enforcement, or device behavior.
"""
import pathlib
import re
import subprocess
import sys
import tempfile

kernel = pathlib.Path(sys.argv[1]) / 'kernel'


def read(name):
    return (kernel / name).read_text()


def function(source, name):
    match = re.search(r'^.*\b' + name + r'\([^;\n]*\)\n\{', source, re.M)
    assert match, name
    end = match.end()
    depth = 1
    while depth:
        if source[end] == '{':
            depth += 1
        elif source[end] == '}':
            depth -= 1
        end += 1
    return source[match.start():end] + '\n'


def no_includes(source):
    return re.sub(r'^#include .*\n', '', source, flags=re.M)


unity = read('ksu.c')
assert '#include "feature/shell_su_adb_only.h"' in unity
assert '#include "feature/shell_su_adb_only.c"' in unity
assert unity.index('ksu_feature_init();') < unity.index('ksu_shell_su_adb_only_init();') < unity.index('ksu_supercalls_init();')
dispatch = read('supercall/dispatch.c')
grant = re.search(r'\.cmd = KSU_IOCTL_GRANT_ROOT,.*?\n    }', dispatch, re.S).group()
assert '.perm_check = allowed_for_su' in grant
assert read('feature/sucompat.c').count('ksu_is_allow_uid_for_current(current_uid().val)') >= 2
feature = read('feature/shell_su_adb_only.c')
assert 'DEFINE_STATIC_KEY_TRUE(ksu_shell_su_adb_only)' in feature
assert 'static_branch_likely(&ksu_shell_su_adb_only)' in feature

stub = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
typedef uint32_t u32;
typedef uint64_t u64;
#define __init
#define __exit
#define __user
#define unlikely(x) (x)
#define likely(x) (x)
#define pr_info(...) ((void)0)
#define pr_warn(...) ((void)0)
#define pr_err(...) ((void)0)
#define pr_debug(...) ((void)0)
#define KERNEL_VERSION(a,b,c) (((a)<<16) + ((b)<<8) + (c))
#define LINUX_VERSION_CODE KERNEL_VERSION(6,6,118)
struct static_key { bool enabled; };
#define DEFINE_STATIC_KEY_TRUE(n) struct { struct static_key key; } n = {{true}}
#define static_branch_likely(p) ((p)->key.enabled)
#define static_key_enabled(p) ((p)->key.enabled)
static void static_key_enable(struct static_key *p) { p->enabled=true; }
static void static_key_disable(struct static_key *p) { p->enabled=false; }
#define DEFINE_MUTEX(n) int n
static void mutex_lock(int *p) { assert(!*p); *p=1; }
static void mutex_unlock(int *p) { assert(*p); *p=0; }
static int rcu_depth, cred_reads;
static void rcu_read_lock(void) { rcu_depth++; }
static void rcu_read_unlock(void) { assert(rcu_depth>0); rcu_depth--; }
#define rcu_dereference(p) (assert(rcu_depth>0), (p))
struct task_security_struct { u32 sid; };
struct cred { const struct task_security_struct *security; uid_t uid; };
struct task_struct { int pid; struct task_struct *real_parent; const struct cred *cred; };
static struct task_struct *current;
static const struct cred *__task_cred(struct task_struct *t) {
    assert(rcu_depth>0); cred_reads++; return t->cred;
}
static const struct cred *current_cred(void) { return current->cred; }
struct kuid { uid_t val; };
static struct kuid current_uid(void) { return (struct kuid){current->cred->uid}; }
static const struct task_security_struct *selinux_cred(const struct cred *c) { return c->security; }
static u32 cached_su_sid, cached_zygote_sid, cached_init_sid, cached_adbd_sid, ksu_file_sid;
static const char *contexts[]={NULL,"u:r:ksu:s0","u:r:adbd:s0","u:r:shell:s0",
    "u:r:zygote:s0","u:r:init:s0","u:object_r:ksu_file:s0","u:r:untrusted_app:s0"};
struct lsm_context { const char *context; u32 len; };
static int __security_secid_to_secctx(u32 sid, struct lsm_context *c) {
    if (!sid || sid>=sizeof(contexts)/sizeof(contexts[0])) return -EINVAL;
    c->context=contexts[sid]; c->len=strlen(c->context); return 0;
}
static void __security_release_secctx(struct lsm_context *c) { (void)c; }
static int security_secctx_to_secid(const char *context, u32 len, u32 *sid) {
    (void)len;
    for (u32 i=1;i<sizeof(contexts)/sizeof(contexts[0]);i++)
        if (!strcmp(context,contexts[i])) { *sid=i; return 0; }
    return -EINVAL;
}
struct app_profile { uid_t curr_uid; bool allow_su; };
struct perm_data { struct app_profile profile; };
static struct perm_data entries[]={{{2000,false}},{{10000,false}}};
#define hash_for_each_possible_rcu(table,p,node,uid) \
    for (p=entries;p<entries+sizeof(entries)/sizeof(entries[0]);p++)
static bool allow_shell;
static bool is_uid_manager(uid_t uid) { return uid==10001; }
static bool is_manager(void) { return is_uid_manager(current_uid().val); }
struct ksu_uid_granted_root_cmd { u32 uid; bool granted; };
static int copy_from_user(void *d,const void *s,size_t n) { memcpy(d,s,n); return 0; }
static int copy_to_user(void *d,const void *s,size_t n) { memcpy(d,s,n); return 0; }
'''

parts = [stub, read('include/uapi/feature.h'), read('policy/feature.h'),
         read('selinux/selinux.h'), no_includes(read('feature/shell_su_adb_only.h')),
         read('policy/feature.c')]
selinux = read('selinux/selinux.c')
parts += [function(selinux, name) for name in
          ('cache_sid', 'is_sid_match', 'is_task_ksu_domain', 'is_ksu_domain', 'is_adbd')]
parts += [no_includes(feature)]
allowlist = read('policy/allowlist.c')
parts += [function(allowlist, name) for name in
          ('forbid_system_uid', '__ksu_is_allow_uid', 'ksu_is_uid_granted_root', '__ksu_is_allow_uid_for_current')]
parts += ['#define ksu_is_allow_uid_for_current(uid) __ksu_is_allow_uid_for_current(uid)\n',
          function(read('supercall/perm.c'), 'allowed_for_su'),
          function(dispatch, 'do_uid_granted_root')]

parts.append(r'''
int main(void) {
    struct task_security_struct s_shell={3},s_adbd={2},s_ksu={1},s_init={5},s_app={7};
    struct cred c_shell={&s_shell,2000},c_adbd={&s_adbd,2000},c_ksu={&s_ksu,0},
                c_init={&s_init,0},c_app={&s_app,10000},c_manager={&s_app,10001},c_no_sid={NULL,0};
    struct task_struct init={1,NULL,&c_init},adbd={10,&init,&c_adbd},
        root={11,&init,&c_ksu},app={12,&init,&c_app},shell={13,&adbd,&c_shell};
    init.real_parent=&init; current=&shell;
    unsigned cases=0; u64 value=0; bool supported=false;
#define CHECK(x) do { assert(x); assert(rcu_depth==0); cases++; } while(0)
    ksu_feature_init(); ksu_shell_su_adb_only_init();
    CHECK(KSU_FEATURE_SHELL_SU_ADB_ONLY==6 && KSU_FEATURE_MAX==7);
    CHECK(ksu_get_feature(6,&value,&supported)==0 && supported && value==1);
    CHECK(ksu_get_feature(5,&value,&supported)==0 && !supported);
    CHECK(ksu_set_feature(5,1)==-EOPNOTSUPP);
    // A trusted source does not grant root without allowlist/debug authorization.
    CHECK(!allowed_for_su());
    entries[0].profile.allow_su=true;
    CHECK(allowed_for_su()); // SID string fallback before cache_sid().
    cache_sid();
    CHECK(cached_adbd_sid==2 && cached_su_sid==1);
    CHECK(allowed_for_su());
    CHECK(!is_adbd(&c_shell) && !is_adbd(NULL) && !is_adbd(&c_no_sid));
    struct task_struct nested={14,&shell,&c_shell}; current=&nested;
    CHECK(allowed_for_su());
    current=&shell; shell.real_parent=&root;
    CHECK(allowed_for_su()); // KSU-domain module daemon remains trusted.
    shell.real_parent=&app;
    CHECK(!allowed_for_su()); // App ancestry cannot inherit shell's grant.
    shell.real_parent=&init;
    CHECK(!allowed_for_su()); // Detached process, even with shell grant.
    struct task_struct fake_adbd={15,&init,&c_init}; shell.real_parent=&fake_adbd;
    CHECK(!allowed_for_su()); // Root uid alone is not a trusted SELinux domain.
    allow_shell=true;
    CHECK(!allowed_for_su()); // Debug allow_shell does not bypass ancestry.
    shell.real_parent=&adbd; entries[0].profile.allow_su=false;
    CHECK(allowed_for_su());
    allow_shell=false;
    CHECK(!allowed_for_su());
    entries[0].profile.allow_su=true;
    // Manager grant query is independent of its (untrusted) ancestry.
    current=&app; app.cred=&c_manager;
    struct ksu_uid_granted_root_cmd query={2000,false};
    CHECK(do_uid_granted_root(&query)==0 && query.granted);
    CHECK(allowed_for_su());
    entries[0].profile.allow_su=false;
    CHECK(do_uid_granted_root(&query)==0 && !query.granted);
    entries[0].profile.allow_su=true;
    app.cred=&c_app;
    CHECK(!allowed_for_su()); entries[1].profile.allow_su=true;
    CHECK(allowed_for_su()); // Ordinary app grants unchanged.
    current=&root; CHECK(allowed_for_su());
    current=&fake_adbd; CHECK(!allowed_for_su()); // Existing uid-0 rule retained.
    // Depth cap counts current as first; no unbounded traversal.
    struct task_struct chain[129];
    for (int i=128;i>=0;i--) chain[i]=(struct task_struct){20+i,i==128?&init:&chain[i+1],&c_shell};
    current=&chain[0]; chain[127].cred=&c_adbd; cred_reads=0;
    CHECK(allowed_for_su() && cred_reads==128);
    chain[127].cred=&c_shell; chain[128].cred=&c_adbd; cred_reads=0;
    CHECK(!allowed_for_su() && cred_reads==128);
    chain[0].real_parent=&chain[0]; cred_reads=0;
    CHECK(!allowed_for_su() && cred_reads==128);
    // Keep upstream feature API, without requiring any new Manager UI.
    current=&shell; shell.real_parent=&init;
    CHECK(ksu_set_feature(6,0)==0); CHECK(allowed_for_su());
    CHECK(ksu_set_feature(6,1)==0); CHECK(!allowed_for_su());
    CHECK(ksu_get_feature(6,&value,&supported)==0 && supported && value==1);
    ksu_shell_su_adb_only_exit(); ksu_feature_exit();
    printf("PASS: %u shell authorization checks; default ON, feature id 6, grant query, SID cache/fallback, ancestry/depth, app and root rules; RCU stubs balanced\n",cases);
}
''')

with tempfile.TemporaryDirectory(prefix='ksu-shell-test-') as tmp:
    source = pathlib.Path(tmp) / 'shell.c'
    binary = pathlib.Path(tmp) / 'shell-test'
    source.write_text('\n'.join(parts))
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-g', str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
