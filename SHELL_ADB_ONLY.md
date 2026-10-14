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

## Verified delivery: 2026-10-14

- Built source: `5ab7492205918fc8901b074355f0f263734e613e`.
- [Actions run 38529481436](https://github.com/taosuyueliang/Build_Lenovo_sm8750/actions/runs/38529481436)
  completed successfully. The new host test passed 32 checks per execution;
  the existing converter test passed 49 executions, including repeats.
- The emitted static key starts at count **1**, Image offset 36,463,616.
- Effective `.config` is identical to the previous timing-fix build.
  Printable-string counts remain 187 SUSFS and 87 KPM; these are presence
  checks, not device functionality tests.
- Raw kernel SHA256:
  `683cf41553a8bb3ea340000f1e5a598c5463f3243ec20f6a9972f0303fc75260`.
- Repacked with the uploaded stock-358 boot, verified SHA256
  `e7b3a286871788f0651ec6c62e7b086b88196968acc5462c42aba71136a1ef71`.
  The complete kernel banner and original AVB metadata were preserved.
- Final boot SHA256:
  `d0c95937f5f3dff8c7acbfd04e41dd232d0030e1635af9ddc74293a3d8f81777`.
  Size: 100,663,296 bytes. Outer AVB and both GKI certificates were resigned
  using the AOSP RSA4096 testkey and independently verified with avbtool.
  magiskboot extraction also reproduced the exact compiled kernel.
- The CI artifact remains an unsigned **raw kernel**. The separately
  delivered `Y700_358_ADBOnly_ON_testkey_20261014.zip` contains the signed
  `boot.img`, evidence, source patches and `repack_boot358.py`.

Full evidence is in `verification/38529481436.json`. Device startup, the
new restriction, SUSFS UI behavior and Native Check remain untested on
hardware. The inherited ZSTD patch rejection and existing SUSFS compiler
warnings remain in the baseline; this result does not claim a warning-free
build or that all inherited optimization patches applied.
