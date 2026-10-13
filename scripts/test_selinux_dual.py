#!/usr/bin/env python3
"""Exercise the actual backported parser/converter with policy and fault stubs.

This checks error handling and ownership, not kernel concurrency or timing.
"""
import pathlib
import subprocess
import sys
import tempfile

source = pathlib.Path(sys.argv[1]).read_text()
start = source.index('static int string_to_context_struct(')
end = source.index('\n/*\n * Write the security context', start)
implementation = source[start:end]

stub = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint32_t u32;
typedef int gfp_t;
#define SECSID_NULL 0
#define GFP_KERNEL 0
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
#define rcu_dereference(p) (p)
struct context { u32 user, role, type; void *mls; };
struct role_datum { u32 value; };
struct user_datum { u32 value; };
struct type_datum { u32 value; int attribute; };
struct symtab { const char *name; void *datum; };
struct policydb {
    struct symtab p_users, p_roles, p_types;
    u32 expected_user, expected_role, expected_type;
    int mls_error, invalid;
};
struct sidtab { int fail, calls; u32 sid; };
struct selinux_policy { struct policydb policydb; struct sidtab *sidtab; };
struct { struct selinux_policy *policy; } selinux_state;
static int allocations, fail_after = -1, validation_calls;
static void *allocate(size_t n) {
    if (fail_after == 0) return NULL;
    if (fail_after > 0) fail_after--;
    void *p = malloc(n); assert(p); allocations++; return p;
}
static void kfree(void *p) { if (p) { allocations--; free(p); } }
static char *kmemdup_nul(const char *s, u32 n, gfp_t flags) {
    (void)flags; char *p = allocate(n+1);
    if (p) { memcpy(p,s,n); p[n]=0; } return p;
}
static void context_init(struct context *c) { memset(c,0,sizeof(*c)); }
static void context_destroy(struct context *c) { kfree(c->mls); c->mls=NULL; }
static void *symtab_search(struct symtab *s, const char *key) {
    return s->datum && strcmp(s->name,key)==0 ? s->datum : NULL;
}
static int mls_context_to_sid(struct policydb *p, char sep, char *text,
                            struct context *c, struct sidtab *s, u32 def) {
    (void)s; (void)def;
    c->mls = allocate(1);
    if (!c->mls) return -ENOMEM;
    if (p->mls_error) return p->mls_error;
    return sep == ':' && strcmp(text,"s0")==0 ? 0 : -EINVAL;
}
static bool policydb_context_isvalid(struct policydb *p, struct context *c) {
    validation_calls++;
    return !p->invalid && c->user==p->expected_user &&
        c->role==p->expected_role && c->type==p->expected_type;
}
static int sidtab_context_to_sid(struct sidtab *s, struct context *c, u32 *sid) {
    (void)c; s->calls++; if (s->fail) return s->fail; *sid=s->sid; return 0;
}
'''
tests = r'''
int main(void) {
    struct user_datum bu={1}, lu={101};
    struct role_datum br={2}, lr={102};
    struct type_datum bt={3,0}, lt={103,0};
    struct sidtab bs={.sid=41}, ls={.sid=82};
    struct selinux_policy backup={.policydb={
        .p_users={"u",&bu},.p_roles={"r",&br},.p_types={"t",&bt},
        .expected_user=1,.expected_role=2,.expected_type=3},.sidtab=&bs};
    struct selinux_policy live={.policydb={
        .p_users={"u",&lu},.p_roles={"r",&lr},.p_types={"t",&lt},
        .expected_user=101,.expected_role=102,.expected_type=103},.sidtab=&ls};
    selinux_state.policy=&live;
    char text[]="u:r:t:s0";
    u32 sid, live_sid; int live_rc, rc, cases=0;
#define CONVERT() security_context_to_sid_with_policy(&backup,text,strlen(text),&sid,0,0)
#define EXPECT(result) do { assert(CONVERT()==(result)); assert(!allocations); cases++; } while(0)
    rc=ksu_security_context_to_sid_dual(&backup,text,strlen(text),&sid,0,0,&live_sid,&live_rc);
    assert(rc==0 && live_rc==0 && sid==41 && live_sid==82);
    assert(bs.calls==1 && ls.calls==1 && validation_calls==2);
    assert(strcmp(text,"u:r:t:s0")==0 && !allocations); cases++;
    for (int i=0;i<32;i++) EXPECT(0);
    live.policydb.mls_error=-EINVAL; EXPECT(-EINVAL);
    live.policydb.mls_error=0;
    live.policydb.p_types.datum=NULL; EXPECT(-EINVAL);
    live.policydb.p_types.datum=&lt;
    backup.policydb.invalid=1; EXPECT(-EINVAL);
    backup.policydb.invalid=0;
    live.policydb.invalid=1; EXPECT(-EINVAL);
    live.policydb.invalid=0;
    ls.fail=-ENOMEM; EXPECT(-ENOMEM); ls.fail=0;
    bs.fail=-ENOMEM; EXPECT(-ENOMEM); bs.fail=0;
    for (int i=0;i<4;i++) { fail_after=i; EXPECT(-ENOMEM); fail_after=-1; }
    const char *bad[]={"", "u", "u:r", "bad:r:t:s0", "u:r:bad:s0", "u:r:t:bad"};
    for (unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++) {
        rc=security_context_to_sid_with_policy(&backup,bad[i],strlen(bad[i]),&sid,0,0);
        assert(rc==-EINVAL && !allocations); cases++;
    }
    puts("PASS: dual-policy ID separation, MLS errors, invalid contexts, allocation failures, SID insertion failures, input preservation, cleanup");
    printf("Cases: %d; outstanding allocations: %d\n",cases,allocations);
}
'''
with tempfile.TemporaryDirectory(prefix='ksu-dual-test-') as tmp:
    test = pathlib.Path(tmp) / 'dual.c'
    binary = pathlib.Path(tmp) / 'dual-test'
    test.write_text(stub + '\n' + implementation + '\n' + tests)
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-g', str(test), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
