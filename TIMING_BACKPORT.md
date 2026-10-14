# Y700 358: reviewable timing-fix candidate

Target: TB322FC, android15-6.6.118, 4 KiB pages. This branch builds an
**unsigned kernel candidate**. It does not claim successful device boot,
Native Check results, or compatibility with every root-detection method.
Final packaging needs the verified 1.5.10.358 stock boot image; the inherited
workflow's 183 boot shell is deliberately rejected for this target.

## Selected baseline

- Build repository baseline: `a7c6025b5ceb55426152b2e03e53781c0b7c8317`.
- SukiSU builtin: `6c284e957feaa9a388a9f1c37dc4ec80d95e434b`.
- cctv18/susfs4oki: `2919a9ad01205c21b1ce346f6fda08a979c58003`, SUSFS v2.3.0.
- Kernel source archive: common/2026-01.tar.gz, SHA256
  `36893cefb1f043da4d679034c9975032cbef150c71b89451603afae3b8d01d62`.
- The existing SukiSU manager package, certificate definitions, SUSFS UI ABI,
  and SID initialization are unchanged. KPM follows the workflow input.
- Existing Unicode and build-identity steps remain enabled.

## Why copying a commit is insufficient

Upstream timing fix: [tiann/KernelSU #3877](https://github.com/tiann/KernelSU/pull/3877),
commit `a85dcbcfc3b09ae410f31aae124d04f3777fdf1c`.
BakaSU's port `fa12ffde8244008e9afdb7ac0c1bb1bc1b06b95a` also validates
the live context against its own policy. SukiSU builtin and SUSFS use manual
hooks in `security/selinux/hooks.c` and `selinuxfs.c`; those call sites must
remain connected to the corrected converter.

The simonpunk SUSFS integration patch at
`bd7d199ac87808001127e8a6d076832e2938cf0d` removes the upstream dual-policy
parser and changes the converter back to six arguments. Therefore a Git
ancestry check alone does not establish that the fix survives integration.

## Changes

1. Backport dual-policy parsing and SID synchronization, preserving the
   six-argument SUSFS API through a wrapper. The old local sidtab shim is
   superseded; it must not be applied on top. It reparsed a buffer already
   modified by the context tokenizer and ignored the synchronization result.
2. Convert `setprocattr(current)` once, use the live SID for the transition,
   and preserve the native SETCURRENT, bounded-transition, DYNTRANSITION,
   and PTRACE permission checks. Other attributes retain the original path.
3. Keep MLS errors, validate each context against its corresponding policy,
   clean up both contexts on all parse outcomes, and propagate live SID
   insertion failures rather than reporting successful synchronization.
4. Regenerate the SUSFS kernel patch against the exact 6.6.118 archive.
   The upstream OKI patch contains two variants of the smaps-rollup hunk;
   this target uses the newer braced variant. Guard both reacquisition cases
   and always advance the iterator boundary for skipped mappings. Remove an
   inapplicable OKI-only conditional inside the open-redirect SRCU section.
5. Rebase the existing auxiliary proc display rules at their intended
   locations outside the open-redirect SRCU section. A fuzzy match must not
   insert a jump out of that locked section. The timing, SUSFS, and auxiliary
   proc patches all use `git apply --check` with no fuzz.

## Evidence and remaining verification

- `scripts/test_selinux_dual.py` compiles the actual parser/converter with
  policy/fault stubs under AddressSanitizer and UndefinedBehaviorSanitizer.
  It exercises separate policy IDs, malformed input, MLS and allocation errors,
  insertion failures, input preservation, and cleanup. It is not a kernel
  concurrency test or a timing benchmark.
- `scripts/verify_timing_source.py` checks the live SUSFS hooks after all
  integration patches, not just the upstream commit history.
- `scripts/verify_candidate.py` checks effective `.config`, linked symbols,
  ARM64 Image format and the expected baseline banner, and records SHA256.
- Actual boot, SUSFS UI operations, the sidtab/timing detector, and matching
  the full stock-358 image metadata require the device and its stock image.

This is a targeted backport of the known issue, not a claim that all changes
from every upstream branch have been merged or that all bugs are fixed.

## Successful build: 2026-10-13

- Tested source commit: `8acd2c9b036b6bc53928c028808b9f147adaf711`.
- [GitHub Actions run 38397756965](https://github.com/taosuyueliang/Build_Lenovo_sm8750/actions/runs/38397756965)
  completed successfully, including the source and linked-image checks.
- Inputs: SukiSU, 6.6.118, SUSFS and KPM enabled; ReKernel, ADIOS, BBG,
  and boot signing disabled; no custom suffix or timestamp.
- Sanitizers: 49 test executions, including 32 repeated valid conversions;
  zero outstanding allocations. These are not 49 distinct device tests.
- Raw kernel: 37,183,200 bytes; SHA256
  `65cbad39dfd63314ceaeda31fb0bd66b91072fe65774b5fecf448b3003d35160`.
- Downloaded artifact ZIP digests match GitHub's recorded digests.
- The complete banner matches the previous successful build byte for byte.
  Using printable ASCII strings of at least four characters, both images
  contain 187 SUSFS strings and 87 KPM strings; raw SUSFS occurrences are
  209 in each. Counts depend on the method and are not functional tests.
- The inherited, unrelated ZSTD optimization patch still reports one
  rejected portability-macro hunk. This build is not evidence that every
  inherited optimization patch applied cleanly.

Machine-readable results are in `verification/38397756965.json`. The
`kernel_image` artifact is a raw kernel, **not a flashable boot.img**.
The `candidate-verification` artifact contains the effective configuration,
System.map, and hashes of the exact patches used for this run.

The small documentation/comment correction after this tested commit does
not change kernel behavior. Subsequent stock-358 repacking and testkey
verification, including the default-on shell restriction added on October
14, are recorded in [SHELL_ADB_ONLY.md](SHELL_ADB_ONLY.md). Successful device
boot and Native Check results remain unverified.
