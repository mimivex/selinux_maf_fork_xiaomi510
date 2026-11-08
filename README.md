# selinux_maf_fork_xiaomi510

A fork of `741afb7/selinux_maf_fork` (v1.1.9.1), itself a Magisk/APatch/KernelSU
port of `Admirepowered/selinux_hook`. GPL-3.0.

This fork targets kernels that do not expose the `selinux_state` symbol in
kallsyms.

Those kernels are still stateful: since 4.17, `security_load_policy()`,
`selinux_policy_commit()` and `context_struct_compute_av()` take a
`struct selinux_state *` as their first argument. But the symbol is absent, so
looking it up to decide the calling convention selects the "legacy" ABI and
hooks the functions with the wrong arguments. This fork derives the ABI from the
kernel version instead (`>= 4.17 && < 6.4`), the same rule as KernelPatch's
`selinux_need_call_compat()`.

The clean-policydb snapshot runs in a kthread rather than from the
`context_struct_compute_av()` hook. That function is reached through
`security_compute_av()` under `rcu_read_lock()`, and the snapshot does
`filp_open()`, `kernel_read()`, `vmalloc()` and `policydb_read()`, all of which
may sleep. Sleeping in an RCU read-side critical section hard-locks the kernel
with no oops: the module loads, then the device freezes a few seconds after the
lock screen and reboots.

## What this fork changes

Relative to upstream v1.1.9.1.

| # | Change | Where | Why |
|---|---|---|---|
| 1 | The stateful SELinux ABI is detected from the kernel version (`4.17`–`6.3`) instead of by looking for `selinux_state` in kallsyms. | `selinux_state_arg_required()` | Kernels that strip the symbol still use the stateful ABI. Probing for it selects the legacy one, and every hooked call then gets the wrong argument layout. |
| 2 | The clean-policydb snapshot is taken from a **kthread** (`kp_selinux_snap`). `SELINUX_ASYNC_SNAPSHOT` (default `1`) controls it; `-DSELINUX_ASYNC_SNAPSHOT=0` puts it back in the hook for comparison. | `clean_snapshot_thread()`, `start_clean_snapshot_thread()` | The snapshot does `filp_open()`, `kernel_read()`, `vmalloc()` and `policydb_read()`, all of which may sleep, and the AV hook runs under `rcu_read_lock()`. Sleeping there is a hard lockup. |
| 3 | **`setprocattr` never enters a clean-eval scope.** A value naming a root-injected context gets `-EINVAL` with `skip_origin` set, before the kernel parses or evaluates anything. `names_privileged_context()` matches `magisk`, `lsposed`, `xposed`, `ksu_file`, `droidspaces`, `msd_app`, `msd_daemon`, `adbroot`. | `names_privileged_context()`, `before_selinux_setprocattr_clean_eval()` | Entering the scope there evaluates a live `scontext` against a `tcontext` parsed out of the clean policydb. The clean policy does not know those contexts anyway, so the honest answer is `-EINVAL` — and returning it before the parse avoids the evaluation that hard-locks the device. |
| 4 | `CLEAN_POLICYDB_ALLOC_SIZE` raised from `0x4000` to `0x10000`. | `selinux_hook.c` | The xiaomi.eu policy does not fit in 16 KiB. |
| 5 | A **stall watchdog** (`kp_selinux_wd`). If AV computations stop advancing for ~3 s it fires the kernel's own `sysrq t` and `sysrq l` (falling back to `show_state_filter(TASK_UNINTERRUPTIBLE)`). `SELINUX_DIAG_WATCHDOG` controls it. | `diag_watchdog_thread()`, `diag_watchdog_start()` | A freeze that produces no log output cannot be localized by correlation alone; the watchdog forces a stack dump into the ring buffer. |
| 6 | `EXTRA_CFLAGS` support, a `.buildflags` stamp and the `debug`, `debug-noredirect` and `debug-snapshotonly` targets. | `selinux_hook/Makefile` | Bisecting a boot hang needs several builds side by side, and the stamp guarantees a debug object can never be relinked under the normal name. |

The access/context probing and the status-page redirection are upstream code and
behave as upstream does.

## Build

The `KernelPatch` submodule must be present:

```bash
git clone --recurse-submodules https://github.com/mimivex/selinux_maf_fork_xiaomi510.git
cd selinux_maf_fork_xiaomi510/selinux_hook
```

Then pick one toolchain:

```bash
# Android NDK
ANDROID_NDK_HOME=/path/to/ndk make

# or a bare-metal aarch64 toolchain (what CI uses)
make TARGET_COMPILE=/path/to/aarch64-none-elf-
```

Output: `selinux_hook_1.1.9.2.kpm`.

## Diagnostic builds

These mirror the bisect that located the freeze. They are for debugging only,
do not run them as your daily driver.

| Target | Extra flags | Output | Isolates |
|---|---|---|---|
| `make` | none | `selinux_hook_1.1.9.2.kpm` | normal build |
| `make debug` | `-DSELINUX_DIAG_TRACE=1 -DSELINUX_DIAG_WATCHDOG=1` | `selinux_hook_1.1.9.2-debug.kpm` | where the stall happens |
| `make debug-noredirect` | as above plus `-DSELINUX_DIAG_NO_REDIRECT=1` | `selinux_hook_1.1.9.2-debug-noredirect.kpm` | "hooks installed" vs "redirect active": hooks stay installed and fire, but never snapshot or redirect |
| `make debug-snapshotonly` | as above plus `-DSELINUX_DIAG_SNAPSHOT_ONLY=1` | `selinux_hook_1.1.9.2-debug-snapshotonly.kpm` | "building the clean policydb" vs "handing it to `context_struct_compute_av()`" |

Each target also rebuilds the normal module afterwards, so the debug artifact
never replaces the release one.

The module version string reports which variant is loaded (`1.1.9.2`,
`1.1.9.2-debug`, `1.1.9.2-debug-noredirect`, `1.1.9.2-debug-snapshotonly`).

### Reading the output

With `SELINUX_DIAG_TRACE` the rare hooks are bracketed with entry/exit lines,
and `context_struct_compute_av()` emits a progress tick every 8192
computations:

```text
[selinux_hook] DIAG tick av=8192 uid=1000 comm=system_server in_scope=0
```

The last `DIAG` line before the log stops names the call that never returned.
With `SELINUX_DIAG_WATCHDOG` a stall additionally produces:

```text
[selinux_hook] DIAG WATCHDOG stalled: progress=... av=...
```

followed by a full task dump. Watch for `DIAG WATCHDOG alive progress=...`
every ~10 s: when those stop, the whole box stopped, not just the module.

## Supported Kernel Versions

selinux_MAF_fork_xiaomi510 is supported on:

- Linux 4.19 or later
- Some Linux 4.14 kernels (reference: 4.14.180 or later)

Kernels that strip the `selinux_state` symbol from kallsyms (for example
Xiaomi 4.19 vendor kernels) are supported: the stateful SELinux ABI is
detected by kernel version (4.17–6.3), matching KernelPatch's
`selinux_need_call_compat()`.

For Linux 4.14 or earlier kernels, support requires the following SELinux
layouts:

`/security/selinux/include/security.h`

```c
extern struct page *selinux_kernel_status_page(struct selinux_state *state);
```

`/security/selinux/ss/services.c`

```c
static void context_struct_compute_av(struct policydb *policydb,
                                      struct context *scontext,
                                      struct context *tcontext,
                                      u16 tclass,
                                      struct av_decision *avd,
                                      struct extended_perms *xperms);
```

<sub>Theoretically, some Linux 4.9 kernels may also be supported (reference: 4.9.223 or later), but they have not been thoroughly tested.</sub>

## Operating Modes

Use the `mode` control parameter to check the current operating mode.

1. NORMAL

The normal operating mode. The kernel supports both `policydb` redirection and
status-page redirection, and the module has successfully captured and loaded a
clean system `policydb`. Access Vector calculations made inside the clean
evaluation scope are redirected to that policy database, shielding them from
Magisk-injected policy changes.

2. POLICYDB_REQ

The kernel supports both `policydb` redirection and status-page redirection,
but the module could not obtain a usable clean `policydb`. No manual AV
calculation or hard-coded access/context filtering is used; SELinux policy
evaluation remains on the kernel's live path.

3. UNSUPORRT

*(sic, the string is spelled this way in the module.)* The kernel does not
support `policydb` redirection. Policy-related redirect and filtering hooks are
disabled, while status-page handling remains independent; the kernel's native
SELinux policy behavior is preserved.

The status-page and clean-policy capture hooks are independent of these mode
labels and may remain active when policydb redirection is unavailable.

## License

GPL-3.0, inherited from the upstream project. See `LICENSE`.
