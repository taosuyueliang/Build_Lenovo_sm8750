# Y700 358: shell root restricted to trusted sessions by default

This extends the tested SukiSU builtin timing-fix baseline with
[KernelSU #3882](https://github.com/tiann/KernelSU/pull/3882), upstream commit
`0a1f3ff71719fa2d6ec15f5568dac27fdb957fcc`.

The upstream feature is optional and initially off. This port deliberately
uses `DEFINE_STATIC_KEY_TRUE` and `static_branch_likely`, so it starts **on**
without a Manager setting, module, or boot script. Feature ID 6 is retained;
ID 5 remains unused to avoid applying an unrelated historic saved value.
The privileged feature API remains compatible with upstream. This is an
enabled default, not an immutable setting that root cannot change.

## Behavior

- A shell (UID 2000) request still needs its existing root grant.
- Additionally, current or an ancestor must have SELinux domain
  `u:r:adbd:s0` or `u:r:ksu:s0`. UID 0 or a process name alone is insufficient.
- The RCU-protected walk stops at init, with a 128-process cap. A shell
  daemon reparented to init loses this eligibility.
- Both sucompat and the GRANT_ROOT permission check use the restriction.
- The Manager's UID_GRANTED_ROOT query keeps its original grant-state
  meaning; it does not depend on the querying Manager's ancestry.
- Ordinary application root grants and the existing uid-0 domain check
  are preserved. SUSFS, KPM, timing/sidtab, Unicode, stock banner, and the
  official SukiSU Manager identity/certificate remain on the same baseline.

The current official SukiSU Manager does not need to display this feature.
No Manager APK is built or replaced. Existing root grants still apply.
Wireless debugging clients that actually pass through adbd are trusted
under this upstream design. KSU-domain module services are trusted too;
this is not a USB-only restriction. Injection into an already trusted
session is outside the protection provided by this feature.

## Verification

`scripts/test_shell_adb_only.py` compiles the actual feature, feature registry,
grant lookup, SELinux SID helpers, permission check, and query handler with
host stubs under AddressSanitizer and UndefinedBehaviorSanitizer. Cases cover
trusted/untrusted ancestry, missing grants, debug allow_shell, SID cache and
fallback, query independence, ordinary applications, existing root domains,
detached processes, exact depth boundaries, and runtime feature state.
This is not an Android kernel concurrency or device test.

The workflow applies this separate patch with `git apply --check`, tests it
again after integration, and retains the existing timing-source checks.
`verify_candidate.py` requires the new linked symbols and reads the static
key's initial value directly from the built raw Image using System.map.
It also checks the effective SUSFS/KPM configuration and baseline banner.

The CI artifact is a raw kernel. It must be repacked into the verified
ZUXOS 1.5.10.358 stock boot and signed separately. Device startup and real
shell authorization tests remain pending until tested on the tablet.
