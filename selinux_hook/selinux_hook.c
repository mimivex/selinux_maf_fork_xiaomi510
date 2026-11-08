/*
 * Audit and filter SELinux access queries that probe Magisk contexts.
 *
 * Transaction queries are filtered at the direct selinuxfs write handlers,
 * where /sys/fs/selinux/access and /sys/fs/selinux/context still have the
 * original query text.  procattr writes are filtered at selinux_setprocattr().
 * Returning -EINVAL for Magisk contexts matches the clean-policy behavior
 * where the Magisk type/context does not exist.
 */

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <asm/current.h>
#include <asm-generic/rwonce.h>
#include <uapi/asm-generic/errno.h>
#include <uapi/asm-generic/fcntl.h>
#include <uapi/linux/fs.h>
#include <security.h>
#include <ksyms.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>

KPM_NAME("selinux_MAF_fork_xiaomi510");
#if SELINUX_DIAG_SNAPSHOT_ONLY
KPM_VERSION(SELINUX_VERSION "-debug-snapshotonly");
#elif SELINUX_DIAG_TRACE && SELINUX_DIAG_NO_REDIRECT
KPM_VERSION(SELINUX_VERSION "-debug-noredirect");
#elif SELINUX_DIAG_TRACE
KPM_VERSION(SELINUX_VERSION "-debug");
#elif SELINUX_DIAG_NO_REDIRECT
KPM_VERSION(SELINUX_VERSION "-noredirect");
#else
KPM_VERSION(SELINUX_VERSION);
#endif
KPM_LICENSE("GPL v3");
KPM_AUTHOR("Admire/741afb7/ddjjll87/mimivex");
KPM_DESCRIPTION("Audit and reject Magisk /sys/fs/selinux/access probes");

#define ACCESS_SAMPLE_MAX 256
#define ACCESS_PROBE_SLOTS 32
#define CLEAN_POLICYDB_ALLOC_SIZE 0x10000
#define SELINUX_LEGACY_BLOB_QUERY_MAX VERSION(4, 15, 0)
#define contains_case_literal(s, len, lit) contains_case_lit((s), (len), (lit), sizeof(lit) - 1)

#define MAGISK_POLICY_PATH "/.magisk/selinux/load"
#define MAGISK_POLICY_REL_PATH ".magisk/selinux/load"
#define MAGISK_POLICY_MAX_SIZE (8 * 1024 * 1024)
#define CLEAN_EVAL_SCOPE_SLOTS 8
#define SELINUX_STATUS_SIZE 20
#define SELINUX_STATUS_CLEAN_SEQUENCE 4
#define SELINUX_STATUS_CLEAN_POLICYLOAD 1
#define KP_AVD_CLEAN_SEQNO 1
#define selinux_hook_dbg(fmt, ...) pr_info(fmt, ##__VA_ARGS__)

typedef enum {
    SEL_HOOK_STATE_NORMAL = 0,
    SEL_HOOK_STATE_POLICYDB_REQ,
    SEL_HOOK_STATE_UNSUPORRT
} sel_hook_state_t;

static void *g_funcs[24];
static void *g_hook_befores[24];
static void *g_hook_afters[24];
static int g_hooks;
static long (*copy_from_kernel_nofault_fn)(void *dst, const void *src, size_t size);
static int (*security_load_policy_fn)(void *data, size_t len, struct selinux_load_state *load_state);
static int (*security_context_to_sid_fn)(const char *scontext, u32 scontext_len, u32 *out_sid, gfp_t gfp);
static int (*security_context_to_sid_compat_fn)(void *state, const char *scontext, u32 scontext_len,
                                                u32 *out_sid, gfp_t gfp);
struct policydb;
struct policy_file {
    char *data;
    size_t len;
};

static int (*policydb_read_fn)(struct policydb *policydb, struct policy_file *fp);
static void (*policydb_destroy_fn)(struct policydb *policydb);
static void *(*vmalloc_fn)(unsigned long size);
static void *(*vmalloc_to_page_fn)(const void *addr);
static void (*vfree_fn)(const void *addr);
static struct file *(*filp_open_fn)(const char *filename, int flags, umode_t mode);
static int (*filp_close_fn)(struct file *filp, fl_owner_t id);
static ssize_t (*kernel_read_fn)(struct file *file, void *buf, size_t count, loff_t *pos);
static loff_t (*vfs_llseek_fn)(struct file *file, loff_t offset, int whence);
static void *g_selinux_state;

static bool g_selinux_ready;
static bool g_dirty_policy_seen;
static void *g_first_policydb;
static u32 g_clean_access_count;
static void *g_clean_policy_blob;
static size_t g_clean_policy_len;
static bool g_clean_policy_has_magisk;
static bool g_clean_policydb_direct;
static void *g_clean_policydb;
static u32 g_clean_eval_depth;
static u32 g_selinux_setprocattr_probe_count;
static bool g_policy_capture_in_progress;

struct access_probe {
    u32 id;
    uid_t uid;
    const char *node;
    char query[ACCESS_SAMPLE_MAX];
};

struct clean_eval_scope {
    void *task;
    u32 depth;
};

static struct access_probe g_probes[ACCESS_PROBE_SLOTS];
static struct clean_eval_scope g_clean_eval_scopes[CLEAN_EVAL_SCOPE_SLOTS];
static unsigned char g_clean_status_bytes[SELINUX_STATUS_SIZE];
static void *g_fake_status_page;
static bool g_status_page_redirect_hooked;

/* Spinlock guards for the scope arrays.  We do not use DEFINE_SPINLOCK +
 * spin_lock() because the running kernel on this device does not export
 * _raw_spin_lock/_raw_spin_unlock through the kfunc ksymtab; the wrapper
 * expands to kf__raw_spin_lock/unknown.  Resolve the raw helpers via
 * kallsyms at init (mirroring vmalloc/vfree/etc.) and call them through
 * a function pointer, matching the convention used elsewhere in this
 * module. */
typedef void (*raw_spin_lock_fn_t)(raw_spinlock_t *lock);
typedef void (*raw_spin_unlock_fn_t)(raw_spinlock_t *lock);
static raw_spin_lock_fn_t g_raw_spin_lock_fn;
static raw_spin_unlock_fn_t g_raw_spin_unlock_fn;
static raw_spinlock_t g_scopes_lock = { .raw_lock = ATOMIC_INIT(0) };

static bool contains_magisk(const char *s, size_t len);
static bool contains_case_lit(const char *s, size_t len, const char *lit, size_t lit_len);
static bool should_bypass_clean_filter(uid_t uid);
static const char *current_comm(void);
static bool use_legacy_clean_blob_query(void);
static bool clean_policydb_redirect_supported(void);
static bool selinux_state_arg_required(void);
static bool selinux_compat_call_needed(void);
static void resolve_required_symbols_once(void);
static void *lookup_name_optional_suffix(const char *base);
static void log_symbol_addr(const char *name, const void *addr);
static void zero_bytes(void *dst, size_t len);
static bool snapshot_magisk_policy_file(const char *reason, bool try_relative);
static bool finish_deferred_policy_capture(hook_fargs4_t *a, const char *stage, bool allow_fallback);
static void before_security_load_policy(hook_fargs4_t *a, void *u);
static void after_security_load_policy(hook_fargs4_t *a, void *u);
static void try_load_clean_policydb_from_blob(const char *reason);
static void snapshot_clean_policy(const char *reason);
static bool enter_clean_eval_scope(void);
static void leave_clean_eval_scope(void);
static bool current_in_clean_eval_scope(void);
static int install_write_op_hooks(void);
static void record_inline_hook(void *func, void *before, void *after);
static void uninstall_inline_hooks(void);
static void before_selinux_kernel_status_page(hook_fargs4_t *a, void *u);
static bool install_status_page_redirect(void);

/*
 * Patch the seqno field (5th whitespace-separated token, formatted as "%u")
 * in a /sys/fs/selinux/access response buffer to new_seqno.
 * Format: "%x %x %x %x %u %x"
 * Returns the new length (may differ if decimal widths differ).
 */
static ssize_t patch_response_seqno(char *buf, ssize_t ret, u32 new_seqno)
{
    char *p = buf;
    char *end = buf + ret;
    char *tok_start;
    char new_str[12];
    int ns_len;
    int tok;
    ssize_t diff;

    if (ret <= 0 || !buf)
        return ret;

    /* Skip 4 space-separated tokens to reach the 5th (seqno) */
    for (tok = 0; tok < 4; tok++) {
        while (p < end && *p == ' ') p++;
        while (p < end && *p != ' ') p++;
    }
    while (p < end && *p == ' ') p++;
    tok_start = p;
    while (p < end && *p != ' ' && *p != '\0' && *p != '\n') p++;

    if (tok_start >= p)
        return ret;

    /* Render new_seqno as decimal */
    {
        u32 v = new_seqno;
        int i = 0;
        char tmp[12];
        if (v == 0) {
            new_str[0] = '0';
            ns_len = 1;
        } else {
            while (v > 0) { tmp[i++] = '0' + (v % 10); v /= 10; }
            for (ns_len = 0; ns_len < i; ns_len++)
                new_str[ns_len] = tmp[i - 1 - ns_len];
        }
    }

    diff = (ssize_t)ns_len - (ssize_t)(p - tok_start);
    if (diff != 0) {
        /* Shift the remainder of the string left or right */
        char *dst = tok_start + ns_len;
        char *src = p;
        size_t move = (size_t)(end - src);
        int j;
        if (diff < 0) {
            for (j = 0; j < (int)move; j++) dst[j] = src[j];
        } else {
            for (j = (int)move - 1; j >= 0; j--) dst[j] = src[j];
        }
        ret += diff;
    }

    {
        int k;
        for (k = 0; k < ns_len; k++)
            tok_start[k] = new_str[k];
    }
    return ret;
}

static void copy_bytes(void *dst, const void *src, size_t len)
{
    size_t i;
    volatile char *d = (volatile char *)dst;
    const volatile char *s = (const volatile char *)src;

    if (!d || !s)
        return;

    for (i = 0; i < len; i++)
        d[i] = s[i];
}

static void zero_bytes(void *dst, size_t len)
{
    size_t i;
    volatile char *d = (volatile char *)dst;

    if (!d)
        return;

    for (i = 0; i < len; i++)
        d[i] = 0;
}

static size_t runtime_page_size(void)
{
    uint64_t tcr_el1;
    uint64_t tg1;

    /* Match KernelPatch's runtime page-size detection for the TTBR1 range. */
    asm volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));
    tg1 = (tcr_el1 >> 30) & 0x3;

    if (tg1 == 1)
        return 16 * 1024;
    if (tg1 == 3)
        return 64 * 1024;
    return 4 * 1024;
}

static void put_u32_le(unsigned char *dst, u32 value)
{
    if (!dst)
        return;

    dst[0] = (unsigned char)(value & 0xff);
    dst[1] = (unsigned char)((value >> 8) & 0xff);
    dst[2] = (unsigned char)((value >> 16) & 0xff);
    dst[3] = (unsigned char)((value >> 24) & 0xff);
}

static u32 get_u32_le(const unsigned char *src)
{
    if (!src)
        return 0;

    return (u32)src[0] |
           ((u32)src[1] << 8) |
           ((u32)src[2] << 16) |
           ((u32)src[3] << 24);
}

static void fill_clean_status_bytes(unsigned char *status)
{
    u32 seq, pload;

    if (!status)
        return;

    /* kernel >= 6.6: detection expects sequence=4 policyload=1
     * kernel <  6.6: detection expects sequence=0 policyload=0
     * (Java isNewKernel() uses >= 6.10 as threshold, we use 6.6 to
     *  be safe and avoid false positives on kernels in between)
     */
    if (kver >= VERSION(6, 7, 0)) {
        seq   = SELINUX_STATUS_CLEAN_SEQUENCE;
        pload = SELINUX_STATUS_CLEAN_POLICYLOAD;
    } else {
        seq   = 0;
        pload = 0;
    }

    zero_bytes(status, SELINUX_STATUS_SIZE);
    put_u32_le(status + 0,  1);
    put_u32_le(status + 4,  seq);
    put_u32_le(status + 8,  1);    /* enforcing — always 1 */
    put_u32_le(status + 12, pload);
    put_u32_le(status + 16, 1);
}

static bool buffer_contains_magisk(const char *buf, size_t len)
{
    return contains_magisk(buf, len);
}

static bool ascii_lower_eq(char a, char b)
{
    if (a >= 'A' && a <= 'Z')
        a = a - 'A' + 'a';
    if (b >= 'A' && b <= 'Z')
        b = b - 'A' + 'a';
    return a == b;
}

static bool str_eq_lit(const char *s, const char *lit)
{
    size_t i;

    if (!s || !lit)
        return false;

    for (i = 0; lit[i]; i++) {
        if (s[i] != lit[i])
            return false;
    }

    return s[i] == '\0';
}

static const char *current_comm(void)
{
    if (task_struct_offset.comm_offset <= 0)
        return "?";

    return get_task_comm(current) ?: "?";
}

static bool should_bypass_clean_filter(uid_t uid)
{
    if (uid < 10000)
        return true;

    return false;
}

/*
 * Diagnostic tracing, enabled only with -DSELINUX_DIAG_TRACE=1.
 *
 * The device freezes with no kernel diagnostics, so the only way to localize
 * the stall is to bracket the rare hooks with entry/exit prints and emit a
 * periodic tick from context_struct_compute_av().  The last DIAG line before
 * dmesg goes silent names the call that never returned.
 */
#if SELINUX_DIAG_WATCHDOG
/* Bumped by every hooked AV computation; read by the stall watchdog. */
static u64 g_diag_progress;
#endif

#if SELINUX_DIAG_TRACE
static u64 g_diag_seq;
static u32 g_diag_av_count;

static u64 diag_next(void)
{
    return ++g_diag_seq;
}

static void diag_av_tick(void)
{
    u32 n = ++g_diag_av_count;

    if ((n & 0x1fff) == 0)
        pr_info("[selinux_hook] DIAG tick av=%u uid=%d comm=%s in_scope=%d\n",
                n, (int)current_uid(), current_comm(),
                current_in_clean_eval_scope() ? 1 : 0);
}
#endif

/*
 * Stall watchdog, enabled only with -DSELINUX_DIAG_WATCHDOG=1 (the 'debug'
 * build enables it together with SELINUX_DIAG_TRACE).
 *
 * The device dies with no oops and no stack trace, so correlation alone
 * cannot tell which lock is held.  A kernel thread polls a progress counter
 * bumped by every context_struct_compute_av(); if nothing moves for ~3 s it
 * fires the kernel's own sysrq handlers, which dump every task's stack and
 * all per-CPU backtraces into the ring buffer.  The kmsg stream already
 * attached during capture writes them to the PC while they happen.
 *
 * The thread is started from module init, which runs at pre-kernel-init, so
 * kthreadd already exists.  Everything is resolved through kallsyms; any
 * missing symbol only disables that part of the watchdog.
 */
typedef int (*kthread_fn_t)(void *data);
typedef void *(*kthread_create_on_node_fn_t)(kthread_fn_t fn, void *data,
                                             int node, const char *namefmt, ...);
typedef int (*wake_up_process_fn_t)(void *task);
typedef void (*msleep_fn_t)(unsigned int msecs);
typedef void (*handle_sysrq_fn_t)(int key);
typedef void (*show_state_filter_fn_t)(unsigned long state);

#if SELINUX_DIAG_WATCHDOG
static volatile bool g_watchdog_stop;
static void *g_watchdog_task;
static kthread_create_on_node_fn_t g_kthread_create_fn;
static wake_up_process_fn_t g_wake_up_process_fn;
static msleep_fn_t g_msleep_fn;
static handle_sysrq_fn_t g_handle_sysrq_fn;
static show_state_filter_fn_t g_show_state_filter_fn;

static void diag_watchdog_dump(void)
{
    pr_warn("[selinux_hook] DIAG WATCHDOG stalled: progress=%llu av=%u\n",
            READ_ONCE(g_diag_progress), READ_ONCE(g_diag_av_count));

    /* 't' prints every task, 'l' prints all per-CPU stacks. */
    if (g_handle_sysrq_fn) {
        g_handle_sysrq_fn('t');
        g_handle_sysrq_fn('l');
    } else if (g_show_state_filter_fn) {
        g_show_state_filter_fn(0x2 /* TASK_UNINTERRUPTIBLE */);
    } else {
        pr_warn("[selinux_hook] DIAG WATCHDOG has no dump primitive available\n");
    }
}

static int diag_watchdog_thread(void *data)
{
    u64 last = READ_ONCE(g_diag_progress);
    bool armed = false; /* nothing is ever computed before boot reaches SELinux */
    unsigned int quiet = 0;
    unsigned int dumps = 0;
    unsigned int ticks = 0;

    pr_info("[selinux_hook] DIAG WATCHDOG thread started\n");
    for (;;) {
        u64 now;

        if (READ_ONCE(g_watchdog_stop))
            return 0;
        if (g_msleep_fn)
            g_msleep_fn(500);

        now = READ_ONCE(g_diag_progress);
        if (now != last) {
            last = now;
            quiet = 0;
            dumps = 0; /* a quiet stretch that ended was not a freeze */
            if (!armed) {
                armed = true;
                pr_info("[selinux_hook] DIAG WATCHDOG armed progress=%llu\n",
                        now);
            }
            /* Alive line every ~10 s: if these stop, the whole box stopped. */
            if ((++ticks % 20) == 0)
                pr_info("[selinux_hook] DIAG WATCHDOG alive progress=%llu\n",
                        now);
            continue;
        }

        /* An idle kernel is normal; only a stall after progress is suspicious. */
        if (!armed)
            continue;

        quiet++;
        /* Six 500 ms windows without a single AV computation. */
        if (quiet >= 6 && dumps < 3) {
            dumps++;
            diag_watchdog_dump();
        } else if (quiet && (quiet % 20) == 0) {
            pr_info("[selinux_hook] DIAG WATCHDOG still quiet for %u ms\n",
                    quiet * 500);
        }
    }
}

static void diag_watchdog_start(void)
{
    g_kthread_create_fn = (kthread_create_on_node_fn_t)
        lookup_name_optional_suffix("kthread_create_on_node");
    g_wake_up_process_fn = (wake_up_process_fn_t)
        lookup_name_optional_suffix("wake_up_process");
    g_msleep_fn = (msleep_fn_t)lookup_name_optional_suffix("msleep");
    g_handle_sysrq_fn = (handle_sysrq_fn_t)
        lookup_name_optional_suffix("handle_sysrq");
    if (!g_handle_sysrq_fn)
        g_show_state_filter_fn = (show_state_filter_fn_t)
            lookup_name_optional_suffix("show_state_filter");

    pr_info("[selinux_hook] DIAG WATCHDOG symbols kthread=%px wake=%px msleep=%px sysrq=%px show_state=%px\n",
            (void *)g_kthread_create_fn, (void *)g_wake_up_process_fn,
            (void *)g_msleep_fn, (void *)g_handle_sysrq_fn,
            (void *)g_show_state_filter_fn);

    if (!g_kthread_create_fn || !g_wake_up_process_fn || !g_msleep_fn)
        return;

    g_watchdog_task = g_kthread_create_fn(diag_watchdog_thread, NULL, -1,
                                          "kp_selinux_wd");
    if (!g_watchdog_task) {
        pr_warn("[selinux_hook] DIAG WATCHDOG kthread create failed\n");
        return;
    }
    g_wake_up_process_fn(g_watchdog_task);
}
#endif

/*
 * Building the clean policydb means filp_open(), kernel_read(), vmalloc() and
 * policydb_read() -- all of which may sleep.  It used to run from the
 * context_struct_compute_av() hook on the first AV computation, but that
 * function is reached through security_compute_av() under rcu_read_lock(),
 * where scheduling is illegal.  On this kernel that is a direct route to a hard
 * lockup with no log output.  Snapshot from a thread instead, and let the
 * early AV computations stay fast.
 */
#ifndef SELINUX_ASYNC_SNAPSHOT
#define SELINUX_ASYNC_SNAPSHOT 1
#endif

#if SELINUX_ASYNC_SNAPSHOT
typedef int (*snap_kthread_fn_t)(void *data);
typedef void *(*snap_kthread_create_fn_t)(snap_kthread_fn_t fn, void *data,
                                          int node, const char *namefmt, ...);
typedef int (*snap_wake_fn_t)(void *task);
typedef void (*snap_msleep_fn_t)(unsigned int msecs);

static void *g_snapshot_task;
static bool g_snapshot_stop;

static int clean_snapshot_thread(void *data)
{
    snap_msleep_fn_t sleep_fn =
        (snap_msleep_fn_t)lookup_name_optional_suffix("msleep");
    int i;

    /* The Magisk-patched policy lands during boot; poll for it. */
    for (i = 0; i < 300 && sleep_fn; i++) {
        if (READ_ONCE(g_snapshot_stop))
            return 0;
        if (READ_ONCE(g_clean_policydb))
            return 0;
        if (READ_ONCE(g_clean_policy_blob)) {
            try_load_clean_policydb_from_blob("async");
            return 0;
        }
        sleep_fn(200);
    }

    if (!READ_ONCE(g_clean_policydb))
        snapshot_clean_policy("async_fallback");
    return 0;
}

static void start_clean_snapshot_thread(void)
{
    snap_kthread_create_fn_t create_fn;
    snap_wake_fn_t wake_fn;

    if (READ_ONCE(g_clean_policydb))
        return;

    create_fn = (snap_kthread_create_fn_t)
        lookup_name_optional_suffix("kthread_create_on_node");
    wake_fn = (snap_wake_fn_t)lookup_name_optional_suffix("wake_up_process");
    if (!create_fn || !wake_fn) {
        pr_warn("[selinux_hook] clean snapshot thread unavailable, falling back to in-hook snapshot\n");
        snapshot_clean_policy("no_thread_fallback");
        return;
    }

    g_snapshot_task = create_fn(clean_snapshot_thread, NULL, -1,
                                "kp_selinux_snap");
    if (!g_snapshot_task) {
        pr_warn("[selinux_hook] clean snapshot thread create failed, falling back to in-hook snapshot\n");
        snapshot_clean_policy("no_thread_fallback");
        return;
    }

    wake_fn(g_snapshot_task);
    pr_info("[selinux_hook] clean snapshot thread started\n");
}
#endif

static bool use_legacy_clean_blob_query(void)
{
    return kver < SELINUX_LEGACY_BLOB_QUERY_MAX;
}

static bool clean_policydb_redirect_supported(void)
{

    /*
     * 4.14 reference basis:
     *   - https://github.com/balgxmr/kernel_xiaomi_cepheus/tree/sixteen
     *   - https://github.com/LineageOS/android_kernel_xiaomi_sm8150/tree/lineage-22.2
     *   - https://android.googlesource.com/kernel/common/+/refs/heads/deprecated/android-4.14-stable
     *
     * Relevant source paths:
     *   - security/selinux/ss/services.c
     *       context_struct_compute_av(struct policydb *policydb, ...)
     *       security_context_to_sid(struct selinux_state *state, ...)
     *       security_load_policy(struct selinux_state *state, ...)
     *   - security/selinux/selinuxfs.c
     *       sel_write_access(), sel_write_context()
     *
     * 这里的 4.14 适配不是单纯按 kver 猜 ABI，而是用上述 cepheus/sm8150
      * 4.14 源码确认 SELinux helper 的真实签名。只要运行时能解析到
      * selinux_state，就认为它符合这组 4.14 stateful SELinux 布局；否则
      * policydb redirect 保持关闭，避免把参数强套到未知布局上。
     *
     * The Xiaomi sm8150/cepheus 4.14 lineage keeps selinux_state and also uses
     * the policydb-argument context_struct_compute_av() signature.  Therefore
     * selinux_state is the runtime confidence signal for using the 4.14
     * stateful SELinux helper signatures and the 6-argument policydb redirect
      * path. Kernels older than this baseline do not install policydb hooks.
     */
    return !use_legacy_clean_blob_query() || g_selinux_state;
}

/*
 * Bisect build (-DSELINUX_DIAG_NO_REDIRECT=1).
 *
 * Keeps every hook installed exactly as the normal build does, but disables
 * everything the hooks do: no clean-policydb snapshot, no clean-eval scope, no
 * policydb argument rewrite.  That separates "having the hooks installed" from
 * "redirecting the caller onto the clean policydb", which the coarser first
 * attempt could not: there the hooks were skipped outright, so the survival of
 * the device only ruled out the load/commit/status-page paths.
 */
static bool clean_redirect_active(void)
{
#if SELINUX_DIAG_NO_REDIRECT
    return false;
#else
    return true;
#endif
}

static bool selinux_compat_call_needed(void)
{
    /*
     * 4.14 参考源码里的 security_context_to_sid() 需要
     * struct selinux_state * 作为第一个参数。
     *
     * 不能依赖 g_selinux_state 符号是否可见。小米 4.19 魔改内核
     * (cepheus/sm8150) 裁剪了 selinux_state 全局符号，但 SELinux 仍是
     * stateful ABI（security_load_policy/selinux_policy_commit 等仍带
     * struct selinux_state * 首参）。KernelPatch 官方
     * selinux_need_call_compat() 也只看 kver 区间（4.17-6.4）。
     *
     * Do not gate on g_selinux_state: a kernel can strip the symbol while
     * keeping the stateful ABI. Keep the state argument through the Android
     * common stateful era, and stop before the newer 6.4+ LSM refactors where
     * this KPM has not been audited.
     */
    return selinux_state_arg_required();
}

static bool selinux_state_arg_required(void)
{
    /*
     * 对齐 KernelPatch 官方 selinux_need_call_compat()：
     *   kver >= 4.17 && kver < 6.4
     * 4.17 起 SELinux 全面 stateful（security_load_policy/
     * selinux_policy_commit 等带 struct selinux_state * 首参）。此判断只看
     * 内核版本，不依赖 selinux_state 符号是否在 kallsyms 可见。
     */
    return kver >= VERSION(4, 17, 0) && kver < VERSION(6, 4, 0);
}

struct symbol_cache_entry {
    const char *base;
    size_t len;
    unsigned long addr;
    bool exact;
    bool suffixed;
};

typedef int (*kallsyms_on_each_symbol_nomod_fn)(int (*fn)(void *, const char *, unsigned long),
                                                void *data);

#define SYMBOL_CACHE_ENTRY(name) { name, 0, 0, false, false }

static struct symbol_cache_entry g_symbol_cache[] = {
    SYMBOL_CACHE_ENTRY("_raw_spin_lock"),
    SYMBOL_CACHE_ENTRY("_raw_spin_unlock"),
    SYMBOL_CACHE_ENTRY("copy_from_kernel_nofault"),
    SYMBOL_CACHE_ENTRY("probe_kernel_read"),
    SYMBOL_CACHE_ENTRY("vmalloc"),
    SYMBOL_CACHE_ENTRY("vmalloc_noprof"),
    SYMBOL_CACHE_ENTRY("vmalloc_to_page"),
    SYMBOL_CACHE_ENTRY("vfree"),
    SYMBOL_CACHE_ENTRY("filp_open"),
    SYMBOL_CACHE_ENTRY("filp_close"),
    SYMBOL_CACHE_ENTRY("kernel_read"),
    SYMBOL_CACHE_ENTRY("vfs_llseek"),
    SYMBOL_CACHE_ENTRY("selinux_state"),
    SYMBOL_CACHE_ENTRY("security_load_policy"),
    SYMBOL_CACHE_ENTRY("security_context_to_sid"),
    SYMBOL_CACHE_ENTRY("policydb_read"),
    SYMBOL_CACHE_ENTRY("policydb_destroy"),
    SYMBOL_CACHE_ENTRY("flex_array_get"),
    SYMBOL_CACHE_ENTRY("avtab_search_node"),
    SYMBOL_CACHE_ENTRY("avtab_search_node_next"),
    SYMBOL_CACHE_ENTRY("cond_compute_av"),
    SYMBOL_CACHE_ENTRY("constraint_expr_eval"),
    SYMBOL_CACHE_ENTRY("type_attribute_bounds_av"),
    SYMBOL_CACHE_ENTRY("selinux_kernel_status_page"),
    SYMBOL_CACHE_ENTRY("selinux_setprocattr"),
    SYMBOL_CACHE_ENTRY("sel_write_access"),
    SYMBOL_CACHE_ENTRY("sel_write_context"),
    SYMBOL_CACHE_ENTRY("context_struct_compute_av"),
    SYMBOL_CACHE_ENTRY("string_to_context_struct"),
    SYMBOL_CACHE_ENTRY("selinux_complete_init"),
    SYMBOL_CACHE_ENTRY("selinux_policy_commit"),
};

#define SYMBOL_CACHE_COUNT (sizeof(g_symbol_cache) / sizeof(g_symbol_cache[0]))

static bool g_symbol_cache_resolved;
static bool g_symbol_cache_walk_complete;

static size_t str_len_safe(const char *s)
{
    const volatile char *p;
    size_t len = 0;

    if (!s)
        return 0;

    /* Keep this as an explicit byte walk so clang/gcc does not fold it into an
     * out-of-line strlen() libcall, which is unavailable in the KPM loader. */
    p = (const volatile char *)s;
    while (p[len])
        len++;
    return len;
}

static bool suffix_contains_cfi(const char *suffix)
{
    size_t i;

    if (!suffix)
        return false;

    for (i = 0; suffix[i]; i++) {
        if (suffix[i] == 'c' && suffix[i + 1] == 'f' && suffix[i + 2] == 'i' &&
            (i == 0 || suffix[i - 1] == '.' || suffix[i - 1] == '$') &&
            (!suffix[i + 3] || suffix[i + 3] == '.' || suffix[i + 3] == '$'))
            return true;
    }
    return false;
}

static bool symbol_name_matches(const char *name, const char *base, size_t len)
{
    size_t i;

    if (!name || !base)
        return false;

    for (i = 0; i < len; i++) {
        if (name[i] != base[i])
            return false;
    }

    return name[len] == '\0';
}

static bool symbol_has_compiler_suffix(const char *name, const char *base, size_t len)
{
    size_t i;

    if (!name || !base || !len)
        return false;

    for (i = 0; i < len; i++) {
        if (name[i] != base[i])
            return false;
    }

    if (!(name[len] == '.' || name[len] == '$') || !name[len + 1])
        return false;

    /* Skip CFI stub variants; they redirect to the real function */
    if (suffix_contains_cfi(name + len + 1))
        return false;

    return true;
}

static void prepare_symbol_cache(void)
{
    size_t i;

    for (i = 0; i < SYMBOL_CACHE_COUNT; i++)
        g_symbol_cache[i].len = str_len_safe(g_symbol_cache[i].base);
}

static void cache_symbol_match(const char *name, unsigned long addr)
{
    size_t i;

    if (!name || !addr)
        return;

    for (i = 0; i < SYMBOL_CACHE_COUNT; i++) {
        struct symbol_cache_entry *entry = &g_symbol_cache[i];

        if (!entry->base || !entry->len || entry->exact)
            continue;

        if (symbol_name_matches(name, entry->base, entry->len)) {
            entry->addr = addr;
            entry->exact = true;
            entry->suffixed = false;
            continue;
        }

        if (!entry->addr &&
            symbol_has_compiler_suffix(name, entry->base, entry->len)) {
            entry->addr = addr;
            entry->suffixed = true;
        }
    }
}

static int cache_symbol_cb(void *data, const char *name,
                           struct module *module, unsigned long addr)
{
    (void)data;
    (void)module;

    cache_symbol_match(name, addr);
    return 0;
}

static int cache_symbol_cb_nomod(void *data, const char *name, unsigned long addr)
{
    (void)data;

    cache_symbol_match(name, addr);
    return 0;
}

static void resolve_required_symbols_once(void)
{
    size_t i;
    u32 found = 0;
    u32 suffixed = 0;
    u32 missing = 0;
    int walk_rc = -ENOENT;
    bool walk_complete = false;

    if (READ_ONCE(g_symbol_cache_resolved))
        return;

    prepare_symbol_cache();

    if (!kallsyms_on_each_symbol) {
        pr_warn("[selinux_hook] kallsyms_on_each_symbol missing; falling back to exact symbol lookups only\n");
        for (i = 0; i < SYMBOL_CACHE_COUNT; i++) {
            unsigned long addr;

            addr = (unsigned long)kallsyms_lookup_name(g_symbol_cache[i].base);
            if (addr) {
                g_symbol_cache[i].addr = addr;
                g_symbol_cache[i].exact = true;
            }
        }
    } else if (kver <= VERSION(6, 1, 0)) {
        walk_rc = kallsyms_on_each_symbol(cache_symbol_cb, NULL);
    } else {
        kallsyms_on_each_symbol_nomod_fn on_each_symbol;

        on_each_symbol = (kallsyms_on_each_symbol_nomod_fn)kallsyms_on_each_symbol;
        walk_rc = on_each_symbol(cache_symbol_cb_nomod, NULL);
    }

	for (i = 0; i < SYMBOL_CACHE_COUNT; i++) {
        if (g_symbol_cache[i].addr) {
            found++;
            if (g_symbol_cache[i].suffixed)
                suffixed++;
        }
    }
    walk_complete = walk_rc == 0 && found > 0;

    if (found == 0 && kallsyms_on_each_symbol) {
        pr_warn("[selinux_hook] kallsyms_on_each_symbol returned no symbols, falling back to kallsyms_lookup_name\n");
        for (i = 0; i < SYMBOL_CACHE_COUNT; i++) {
            unsigned long addr;
            addr = (unsigned long)kallsyms_lookup_name(g_symbol_cache[i].base);
            if (addr) {
                g_symbol_cache[i].addr = addr;
                g_symbol_cache[i].exact = true;
            }
        }
    }

    found = 0;
    suffixed = 0;
    missing = 0;
    for (i = 0; i < SYMBOL_CACHE_COUNT; i++) {
        if (g_symbol_cache[i].addr) {
            found++;
            if (g_symbol_cache[i].suffixed)
                suffixed++;
        } else {
            missing++;
        }
    }

    WRITE_ONCE(g_symbol_cache_walk_complete, walk_complete);
    WRITE_ONCE(g_symbol_cache_resolved, true);
    pr_info("[selinux_hook] symbol cache resolved in one pass: found=%u suffixed=%u missing=%u\n",
            found, suffixed, missing);
}

static struct symbol_cache_entry *find_cached_symbol(const char *base)
{
    size_t i;

    if (!base)
        return NULL;

    for (i = 0; i < SYMBOL_CACHE_COUNT; i++) {
        if (str_eq_lit(base, g_symbol_cache[i].base))
            return &g_symbol_cache[i];
    }

    return NULL;
}

static void *lookup_name_optional_suffix(const char *base)
{
    struct symbol_cache_entry *entry;
    unsigned long addr;

    if (!base)
        return NULL;

    resolve_required_symbols_once();

    entry = find_cached_symbol(base);
    if (entry && entry->addr)
        return (void *)entry->addr;

    addr = (unsigned long)kallsyms_lookup_name(base);
    if (addr && entry) {
        entry->addr = addr;
        entry->exact = true;
        entry->suffixed = false;
    }

    return (void *)addr;
}

/*
 * Some LTO kernels expose context_struct_compute_av only as a numbered local
 * symbol (for example context_struct_compute_av.72).  Keep this expensive
 * fallback out of the generic lookup path: when kallsyms_on_each_symbol is
 * unusable, probing 256 names for every missing cache entry can stall the
 * synchronous pre-kernel-init KPM loader.
 */
static void *lookup_name_numbered_suffix(const char *base)
{
    struct symbol_cache_entry *entry;
    unsigned long addr;
    char name[64];
    volatile char *name_bytes = (volatile char *)name;
    const volatile char *base_bytes = (const volatile char *)base;
    size_t base_len;
    size_t i;
    size_t pos;
    u32 n;

    if (!base)
        return NULL;

    resolve_required_symbols_once();

    if (READ_ONCE(g_symbol_cache_walk_complete))
        return NULL;

    base_len = str_len_safe(base);
    /* Dot, up to three decimal digits, and the trailing NUL. */
    if (!base_len || base_len + 5 > sizeof(name))
        return NULL;

    /* Volatile byte copies keep clang from lowering this into an unresolved
     * out-of-line memcpy() call in the freestanding KPM image. */
    for (i = 0; i < base_len; i++)
        name_bytes[i] = base_bytes[i];

    for (n = 0; n < 256; n++) {
        pos = base_len;
        name[pos++] = '.';
        if (n >= 100)
            name[pos++] = '0' + (n / 100) % 10;
        if (n >= 10)
            name[pos++] = '0' + (n / 10) % 10;
        name[pos++] = '0' + n % 10;
        name[pos] = '\0';

        addr = (unsigned long)kallsyms_lookup_name(name);
        if (addr) {
            entry = find_cached_symbol(base);
            if (entry) {
                entry->addr = addr;
                entry->exact = false;
                entry->suffixed = true;
            }
            pr_info("[selinux_hook] resolved %s as %s addr=%px\n",
                    base, name, (void *)addr);
            return (void *)addr;
        }
    }

    return NULL;
}

static void log_symbol_addr(const char *name, const void *addr)
{
    pr_info("[selinux_hook] symbol %-36s %s addr=%px\n",
            name ?: "(null)", addr ? "found" : "missing", addr);
}

static ssize_t call_kernel_read_file(struct file *file, void *buf, size_t count, loff_t *pos)
{
    if (!kernel_read_fn)
        return -ENOENT;

    if (kver < VERSION(4, 14, 0)) {
        loff_t offset = pos ? *pos : 0;
        int (*kernel_read_legacy)(struct file *file, loff_t offset, char *addr,
                                  unsigned long count) =
            (void *)kernel_read_fn;
        int rc = kernel_read_legacy(file, offset, (char *)buf,
                                    (unsigned long)count);

        if (pos && rc > 0)
            *pos = offset + rc;
        return rc;
    }

    return kernel_read_fn(file, buf, count, pos);
}

static bool snapshot_policy_file_path(const char *path, const char *source,
                                      const char *reason)
{
    struct file *filp;
    void *data;
    loff_t len;
    loff_t pos;
    ssize_t nread;

    if (!vmalloc_fn)
        return false;
    if (!filp_open_fn || !filp_close_fn || !kernel_read_fn || !vfs_llseek_fn) {
        pr_warn("[selinux_hook] CLEAN Magisk policy file read disabled reason=%s open=%px close=%px read=%px llseek=%px\n",
                reason ?: "(null)", filp_open_fn, filp_close_fn,
                kernel_read_fn, vfs_llseek_fn);
        return false;
    }

    filp = filp_open_fn(path, O_RDONLY, 0);
    if (!filp || IS_ERR(filp)) {
        pr_warn("[selinux_hook] CLEAN Magisk policy open failed reason=%s source=%s path=%s rc=%ld\n",
                reason ?: "(null)", source ?: "unknown", path,
                filp ? PTR_ERR(filp) : -ENOENT);
        return false;
    }

    len = vfs_llseek_fn(filp, 0, SEEK_END);
    if (len <= 0 || len > MAGISK_POLICY_MAX_SIZE) {
        pr_warn("[selinux_hook] CLEAN Magisk policy bad len reason=%s source=%s path=%s len=%lld\n",
                reason ?: "(null)", source ?: "unknown", path, len);
        filp_close_fn(filp, 0);
        return false;
    }
    vfs_llseek_fn(filp, 0, SEEK_SET);

    data = vmalloc_fn((unsigned long)len);
    if (!data) {
        pr_warn("[selinux_hook] CLEAN Magisk policy alloc failed reason=%s source=%s len=%lld\n",
                reason ?: "(null)", source ?: "unknown", len);
        filp_close_fn(filp, 0);
        return false;
    }

    pos = 0;
    nread = call_kernel_read_file(filp, data, (size_t)len, &pos);
    filp_close_fn(filp, 0);
    if (nread != len || pos != len) {
        pr_warn("[selinux_hook] CLEAN Magisk policy read failed reason=%s source=%s read=%ld pos=%lld len=%lld\n",
                reason ?: "(null)", source ?: "unknown", (long)nread, pos, len);
        if (vfree_fn)
            vfree_fn(data);
        return false;
    }

    WRITE_ONCE(g_clean_policy_has_magisk, buffer_contains_magisk(data, (size_t)len));
    WRITE_ONCE(g_clean_policy_len, (size_t)len);
    WRITE_ONCE(g_clean_policy_blob, data);
    pr_info("[selinux_hook] CLEAN Magisk policy snapshot saved reason=%s source=%s path=%s blob=%px len=%zu has_magisk=%d\n",
            reason ?: "(null)", source ?: "unknown", path, data,
            READ_ONCE(g_clean_policy_len), READ_ONCE(g_clean_policy_has_magisk));
    return true;
}

static bool snapshot_magisk_policy_file(const char *reason, bool try_relative)
{
    if (snapshot_policy_file_path(MAGISK_POLICY_PATH, "magisk_file_abs", reason))
        return true;
    if (try_relative &&
        snapshot_policy_file_path(MAGISK_POLICY_REL_PATH, "magisk_file_rel", reason))
        return true;
    return false;
}

static void try_load_clean_policydb_from_blob(const char *reason)
{
    struct policy_file fp;
    struct policydb *policydb;
    void *blob = READ_ONCE(g_clean_policy_blob);
    size_t len = READ_ONCE(g_clean_policy_len);
    int rc;

    if (READ_ONCE(g_clean_policydb))
        return;
    if (!blob || !len)
        return;
    if (!policydb_read_fn || !policydb_destroy_fn || !vmalloc_fn)
        return;

    policydb = (struct policydb *)vmalloc_fn(CLEAN_POLICYDB_ALLOC_SIZE);
    if (!policydb) {
        pr_warn("[selinux_hook] CLEAN policydb_read alloc failed reason=%s size=%u\n",
                reason ?: "(null)", CLEAN_POLICYDB_ALLOC_SIZE);
        return;
    }
    zero_bytes(policydb, CLEAN_POLICYDB_ALLOC_SIZE);

    fp.data = (char *)blob;
    fp.len = len;
    rc = policydb_read_fn(policydb, &fp);
    if (rc) {
        pr_warn("[selinux_hook] CLEAN policydb_read failed reason=%s rc=%d policydb=%px blob=%px len=%zu\n",
                reason ?: "(null)", rc, policydb, blob, len);
        if (policydb_destroy_fn)
            policydb_destroy_fn(policydb);
        if (vfree_fn)
            vfree_fn(policydb);
        return;
    }

    WRITE_ONCE(g_clean_policydb, policydb);
    WRITE_ONCE(g_clean_policydb_direct, true);
    pr_info("[selinux_hook] CLEAN policydb_read saved reason=%s policydb=%px blob=%px len=%zu alloc=%u\n",
            reason ?: "(null)", policydb, blob, len, CLEAN_POLICYDB_ALLOC_SIZE);
}

static void activate_clean_policy_blob(const char *reason)
{
    if (READ_ONCE(g_clean_policy_blob) && READ_ONCE(g_clean_policy_len))
        try_load_clean_policydb_from_blob(reason);
}

static void snapshot_clean_policy(const char *reason)
{
    if (!clean_redirect_active()) {
        /* Bisect build: never build a clean policydb, nothing can redirect. */
        (void)reason;
        return;
    }
#if SELINUX_DIAG_TRACE
    pr_info("[selinux_hook] DIAG snapshot-IN reason=%s uid=%d comm=%s\n",
            reason ?: "(null)", (int)current_uid(), current_comm());
#endif
    if (READ_ONCE(g_clean_policy_blob))
        return;
    if (READ_ONCE(g_dirty_policy_seen))
        return;

    /*
     * 只尝试 Magisk 策略文件快照，不主动调用 security_read_policy()。
     *
     * 小米 4.19 魔改内核裁剪了 selinux_state 符号，本模块通过
     * kallsyms 解析不到它。stateful 的 security_read_policy(state, ...)
     * 会解引用首参（反汇编可见 ldr x23,[x0,#0x18]），以 NULL state 调用
     * 会触发 NULL 解引用 panic，导致启动卡在第一屏。
     *
     * 干净策略改由 finish_deferred_policy_capture() 在
     * security_load_policy() 的 after 阶段捕获参数获得（boot 早期
     * 第一次加载的就是系统初始干净策略）。
     */
    if (!snapshot_magisk_policy_file(reason, true))
        return;

    activate_clean_policy_blob(reason);
}

static bool finish_deferred_policy_capture(hook_fargs4_t *a, const char *stage,
                                           bool allow_fallback)
{
    void *data = NULL;
    size_t len = 0;

    if (READ_ONCE(g_clean_policy_blob))
        return true;
    if (READ_ONCE(g_dirty_policy_seen))
        return false;

    /*
     * hook 路径（a != NULL）不尝试文件快照：security_load_policy 调用
     * 时执行 filp_open 有锁序/阻塞风险，且 APatch 上该文件本就不存在。
     * 文件快照只在非 hook 路径（snapshot_clean_policy）尝试。
     */
    if (!a && snapshot_magisk_policy_file(stage, true)) {
        activate_clean_policy_blob(stage);
        return READ_ONCE(g_clean_policy_blob) != NULL;
    }

    if (!allow_fallback) {
        selinux_hook_dbg("[selinux_hook] CLEAN Magisk policy unavailable during %s; waiting for after security_load_policy\n",
                         stage ?: "before");
        return false;
    }

    if (!a)
        return false;

    /*
     * 参数布局：小米 4.19 魔改内核裁剪了 selinux_state 符号，但
     * security_load_policy() 仍是 stateful 签名 (state, data, len, load_state)。
     * selinux_compat_call_needed() 修正后（4.17-6.4 stateful），compat 路径
     * 直接按 (state, data, len) 取参。非 compat（legacy 内核）按
     * (data, len, load_state) 取参，失败时再试 stateful 布局兜底。
     */
    if (selinux_compat_call_needed()) {
        data = (void *)a->arg1;
        len = (size_t)a->arg2;
    } else {
        data = (void *)a->arg0;
        len = (size_t)a->arg1;
        if (!data || !len || len > MAGISK_POLICY_MAX_SIZE) {
            /* Some devices use stateful layouts but do not export the
             * `selinux_state` symbol; this branch handles that case. */
            data = (void *)a->arg1;
            len = (size_t)a->arg2;
        }
    }

    if (!data || !len || len > MAGISK_POLICY_MAX_SIZE || !vmalloc_fn) {
        pr_warn("[selinux_hook] CLEAN security_load_policy fallback rejected stage=%s data=%px len=%zu vmalloc=%px\n",
                stage ?: "after", data, len, vmalloc_fn);
        return false;
    }

    {
        void *src = data;
        void *copy = vmalloc_fn((unsigned long)len);

        if (!copy) {
            pr_warn("[selinux_hook] CLEAN security_load_policy fallback alloc failed stage=%s len=%zu\n",
                    stage ?: "after", len);
            return false;
        }
        copy_bytes(copy, src, len);
        data = copy;
    }
    if (!data) {
        pr_warn("[selinux_hook] CLEAN security_load_policy fallback alloc failed stage=%s len=%zu\n",
                stage ?: "after", len);
        return false;
    }

    WRITE_ONCE(g_clean_policy_has_magisk, buffer_contains_magisk(data, len));

    /*
     * 拒绝含 magisk 字符串的策略：APatch/folkpatch 的 apd 在 post-fs-data
     * 阶段把规则合入策略后调用 security_load_policy，此时参数已是 dirty
     * 策略。如果捕获到这种 blob，把它当干净策略只会让后续重定向失效。
     * boot 早期第一次加载的系统初始策略不含这些 token，若这都含 magisk
     * 说明厂商 ROM 本身带 magisk 规则，此时放弃捕获更安全。
     */
    if (READ_ONCE(g_clean_policy_has_magisk)) {
        pr_warn("[selinux_hook] CLEAN policy capture rejected stage=%s: blob contains magisk token, keeping live policy\n",
                stage ?: "security_load_policy");
        if (vfree_fn)
            vfree_fn(data);
        return false;
    }

    WRITE_ONCE(g_clean_policy_len, len);
    WRITE_ONCE(g_clean_policy_blob, data);
    pr_warn("[selinux_hook] CLEAN policy captured from security_load_policy args stage=%s blob=%px len=%zu has_magisk=%d\n",
            stage ?: "after", data, len, READ_ONCE(g_clean_policy_has_magisk));
    activate_clean_policy_blob(stage ?: "security_load_policy");
    return true;
}

static void before_security_load_policy(hook_fargs4_t *a, void *u)
{
#if SELINUX_DIAG_TRACE
    pr_info("[selinux_hook] DIAG load_policy-IN uid=%d comm=%s\n",
            (int)current_uid(), current_comm());
#endif
    if (READ_ONCE(g_clean_policy_blob) || g_policy_capture_in_progress)
        return;

    /*
     * before 阶段不抓参数也不做文件快照：security_load_policy 持有
     * policy 锁，此时做 filp_open 文件 IO 或 vmalloc 复制可能死锁。
     * 参数捕获放到 after 阶段（allow_fallback=true），此时锁已释放；
     * 文件快照只在非 hook 路径（snapshot_clean_policy）尝试。
     */
    g_policy_capture_in_progress = true;
    finish_deferred_policy_capture(a, "before_security_load_policy", false);
    g_policy_capture_in_progress = false;
}

static void after_security_load_policy(hook_fargs4_t *a, void *u)
{
#if SELINUX_DIAG_TRACE
    pr_info("[selinux_hook] DIAG load_policy-OUT ret=%ld\n",
            a ? (long)a->ret : -1L);
#endif
    if (READ_ONCE(g_clean_policy_blob) || g_policy_capture_in_progress)
        return;
    if (a && (long)a->ret)
        return;

    g_policy_capture_in_progress = true;
    finish_deferred_policy_capture(a, "after_security_load_policy", true);
    g_policy_capture_in_progress = false;
}

static bool contains_magisk(const char *s, size_t len)
{
    return contains_case_literal(s, len, "magisk");
}

/*
 * Contexts that only exist because something patched the live policy.  The
 * clean policy does not know any of them, so a probe naming one must fail the
 * same way it would on a stock device: -EINVAL from the context parser.
 */
static bool names_privileged_context(const char *s, size_t len)
{
    if (!s || !len)
        return false;

    return contains_case_literal(s, len, "magisk") ||
           contains_case_literal(s, len, "lsposed") ||
           contains_case_literal(s, len, "xposed") ||
           contains_case_literal(s, len, "ksu_file") ||
           contains_case_literal(s, len, "droidspaces") ||
           contains_case_literal(s, len, "msd_app") ||
           contains_case_literal(s, len, "msd_daemon") ||
           contains_case_literal(s, len, "adbroot");
}

static bool contains_case_lit(const char *s, size_t len, const char *lit, size_t lit_len)
{
    size_t i;
    size_t j;

    if (!s || !lit || !lit_len || len < lit_len)
        return false;

    for (i = 0; i + lit_len <= len; i++) {
        for (j = 0; j < lit_len; j++) {
            if (!ascii_lower_eq(s[i + j], lit[j]))
                break;
        }
        if (j == lit_len)
            return true;
    }

    return false;
}

static size_t sanitize_query_sample(char *dst, size_t size)
{
    size_t i;

    if (!dst)
        return 0;

    for (i = 0; i < size && i < ACCESS_SAMPLE_MAX - 1; i++) {
        char c = dst[i];

        if (!c)
            break;
        if (c == '\n' || c == '\r' || c == '\t')
            c = ' ';
        dst[i] = c;
    }

    dst[i] = '\0';
    return i;
}

static size_t copy_query_sample(char *dst, const char *src, size_t size)
{
    size_t limit;
    long copied;

    if (!dst || !src)
        return 0;

    limit = size;
    if (!limit || limit > ACCESS_SAMPLE_MAX - 1)
        limit = ACCESS_SAMPLE_MAX - 1;

    dst[0] = '\0';

    if (copy_from_kernel_nofault_fn &&
        copy_from_kernel_nofault_fn(dst, src, limit) == 0) {
        dst[limit] = '\0';
        return sanitize_query_sample(dst, limit);
    }

    copied = compat_strncpy_from_user(dst, (const char __user *)src, limit + 1);
    if (copied <= 0) {
        dst[0] = '\0';
        return 0;
    }

    if ((size_t)copied > limit)
        copied = limit;
    return sanitize_query_sample(dst, (size_t)copied);
}

static bool enter_clean_eval_scope(void)
{
    void *task = current;
    int empty = -1;
    int i;
    u32 depth;
    bool entered = false;

#if SELINUX_DIAG_SNAPSHOT_ONLY
    /*
     * Bisect level 3 (-DSELINUX_DIAG_SNAPSHOT_ONLY=1): the clean policydb is
     * still snapshotted exactly like the normal build, but no task ever enters
     * a clean-eval scope, so context_struct_compute_av() is never handed the
     * clean policydb.  Separates the snapshot itself from the redirect.
     */
    return false;
#endif
    if (!clean_redirect_active())
        return false;
    if (!clean_policydb_redirect_supported())
        return false;
    if (!READ_ONCE(g_clean_policydb))
        return false;

    if (g_raw_spin_lock_fn)
        g_raw_spin_lock_fn(&g_scopes_lock);
    for (i = 0; i < CLEAN_EVAL_SCOPE_SLOTS; i++) {
        if (g_clean_eval_scopes[i].task == task) {
            depth = g_clean_eval_scopes[i].depth + 1;
            g_clean_eval_scopes[i].depth = depth;
            WRITE_ONCE(g_clean_eval_depth, READ_ONCE(g_clean_eval_depth) + 1);
            entered = true;
            break;
        }
        if (empty < 0 && !g_clean_eval_scopes[i].task)
            empty = i;
    }

    if (!entered) {
        if (empty < 0) {
            if (g_raw_spin_unlock_fn)
        g_raw_spin_unlock_fn(&g_scopes_lock);
            pr_warn("[selinux_hook] clean eval scope slots exhausted task=%px comm=%s\n",
                    task, current_comm());
            return false;
        }
        g_clean_eval_scopes[empty].task = task;
        g_clean_eval_scopes[empty].depth = 1;
        WRITE_ONCE(g_clean_eval_depth, READ_ONCE(g_clean_eval_depth) + 1);
        entered = true;
    }
    if (g_raw_spin_unlock_fn)
        g_raw_spin_unlock_fn(&g_scopes_lock);
    return true;
}

static void leave_clean_eval_scope(void)
{
    void *task = current;
    int i;
    u32 depth;

    if (g_raw_spin_lock_fn)
        g_raw_spin_lock_fn(&g_scopes_lock);
    for (i = 0; i < CLEAN_EVAL_SCOPE_SLOTS; i++) {
        if (g_clean_eval_scopes[i].task != task)
            continue;

        depth = g_clean_eval_scopes[i].depth;
        if (depth > 1) {
            g_clean_eval_scopes[i].depth = depth - 1;
        } else {
            g_clean_eval_scopes[i].depth = 0;
            g_clean_eval_scopes[i].task = NULL;
        }
        if (READ_ONCE(g_clean_eval_depth))
            WRITE_ONCE(g_clean_eval_depth, READ_ONCE(g_clean_eval_depth) - 1);
        if (g_raw_spin_unlock_fn)
        g_raw_spin_unlock_fn(&g_scopes_lock);
        return;
    }
    if (g_raw_spin_unlock_fn)
        g_raw_spin_unlock_fn(&g_scopes_lock);
}

static bool current_in_clean_eval_scope(void)
{
    void *task = current;
    int i;
    bool in_scope = false;

    if (g_raw_spin_lock_fn)
        g_raw_spin_lock_fn(&g_scopes_lock);
    for (i = 0; i < CLEAN_EVAL_SCOPE_SLOTS; i++) {
        if (g_clean_eval_scopes[i].task == task &&
            g_clean_eval_scopes[i].depth) {
            in_scope = true;
            break;
        }
    }
    if (g_raw_spin_unlock_fn)
        g_raw_spin_unlock_fn(&g_scopes_lock);
    return in_scope;
}

/* Hook: selinux_complete_init */
static void after_selinux_complete_init(hook_fargs0_t *a, void *u)
{
    WRITE_ONCE(g_selinux_ready, true);
    selinux_hook_dbg("[selinux_hook] SELinux complete_init done\n");
    snapshot_clean_policy("complete_init");
}

/* Hook: selinux_policy_commit */
static void after_selinux_policy_commit(hook_fargs2_t *a, void *u)
{
    WRITE_ONCE(g_selinux_ready, true);
    selinux_hook_dbg("[selinux_hook] SELinux policy committed, first policydb=%px clean policydb=%px\n",
                     g_first_policydb, READ_ONCE(g_clean_policydb));
    snapshot_clean_policy("policy_commit");
}

static void before_policydb_arg0(hook_fargs6_t *a, void *u)
{
    void *policydb = (void *)a->arg0;
    void *clean_policydb = READ_ONCE(g_clean_policydb);
    bool bypass = should_bypass_clean_filter(current_uid());

#if SELINUX_DIAG_TRACE
    diag_av_tick();
#endif
#if SELINUX_DIAG_WATCHDOG
    WRITE_ONCE(g_diag_progress, READ_ONCE(g_diag_progress) + 1);
#endif

    if (!clean_policydb_redirect_supported())
        return;

    /* Bisect build: the hook stays installed and fires, but never redirects
     * and never snapshots a clean policy. */
    if (!clean_redirect_active())
        return;

    if (bypass)
        return;

    /*
     * Only calls running in an explicit clean-eval scope may redirect policydb
     * input.  The scope is tied to current so unrelated callers on other tasks
     * remain observational and keep using the live policydb.
     */
    if (current_in_clean_eval_scope() && clean_policydb) {
#if SELINUX_DIAG_TRACE
        pr_info("[selinux_hook] DIAG av-redirect uid=%d comm=%s live=%px clean=%px\n",
                (int)current_uid(), current_comm(), policydb, clean_policydb);
#endif
        a->arg0 = (uint64_t)clean_policydb;
        return;
    }

    if (!policydb)
        return;

    if (!READ_ONCE(g_selinux_ready)) {
        WRITE_ONCE(g_selinux_ready, true);
        selinux_hook_dbg("[selinux_hook] SELinux ready inferred from context_struct_compute_av\n");
    }

    if (!READ_ONCE(g_first_policydb)) {
        WRITE_ONCE(g_first_policydb, policydb);
        selinux_hook_dbg("[selinux_hook] SAVED first policydb @ %px\n", g_first_policydb);
#if !SELINUX_ASYNC_SNAPSHOT
        /* Sleeping file I/O inside security_compute_av()'s RCU read section. */
        snapshot_clean_policy("first_compute_av");
#endif
        return;
    }

    if (!READ_ONCE(g_dirty_policy_seen) &&
        policydb != READ_ONCE(g_first_policydb) &&
        policydb != READ_ONCE(g_clean_policydb)) {
        WRITE_ONCE(g_dirty_policy_seen, true);
        selinux_hook_dbg("[selinux_hook] policydb changed %px -> %px, Magisk access probes will hit clean-policy EINVAL\n",
                         g_first_policydb, policydb);
    }
}

/* Hook: /sys/fs/selinux/access write handler */
static void before_sel_write_access(hook_fargs4_t *a, void *u)
{
    // if (current_uid() < 10000 || current_is_policy_manager()) {
    //     return; 
    // }
    // pr_info("[selinux_hook] before_sel_write_access called uid=%u\n", current_uid());
    const char *query = (const char *)a->arg1;
    size_t size = (size_t)a->arg2;
    char sample[ACCESS_SAMPLE_MAX];
    u32 slot;
    u32 n;
    uid_t uid;

    a->local.data0 = 0;

    uid = current_uid();
    copy_query_sample(sample, query, size);

    if (should_bypass_clean_filter(uid))
        return;

    n = READ_ONCE(g_clean_access_count) + 1;
    WRITE_ONCE(g_clean_access_count, n);

#if SELINUX_DIAG_TRACE
    pr_info("[selinux_hook] DIAG access-IN #%u uid=%d comm=%s size=%zu query=\"%s\"\n",
            n, (int)uid, current_comm(), size, sample);
#endif

    /* Run the original selinuxfs write handler under the current task's clean scope. */
    a->local.data0 = 3;
    a->local.data1 = n;
    slot = n & (ACCESS_PROBE_SLOTS - 1);
    a->local.data2 = slot;
    g_probes[slot].id = n;
    g_probes[slot].uid = uid;
    g_probes[slot].node = "access";
    copy_bytes(g_probes[slot].query, sample, ACCESS_SAMPLE_MAX);
    if (enter_clean_eval_scope()) {
        a->local.data3 = 1;
    } else {
        a->local.data0 = 0;
    }
}

/* Hook: /sys/fs/selinux/context write handler */
static void before_sel_write_context(hook_fargs4_t *a, void *u)
{
    const char *query = (const char *)a->arg1;
    size_t size = (size_t)a->arg2;
    char sample[ACCESS_SAMPLE_MAX];
    u32 slot;
    u32 n;
    uid_t uid;

    a->local.data0 = 0;

    uid = current_uid();
    copy_query_sample(sample, query, size);

    if (should_bypass_clean_filter(uid))
        return;

    n = READ_ONCE(g_clean_access_count) + 1;
    WRITE_ONCE(g_clean_access_count, n);

#if SELINUX_DIAG_TRACE
    pr_info("[selinux_hook] DIAG context-IN #%u uid=%d comm=%s size=%zu query=\"%s\"\n",
            n, (int)uid, current_comm(), size, sample);
#endif

    a->local.data1 = n;
    slot = n & (ACCESS_PROBE_SLOTS - 1);
    a->local.data2 = slot;
    g_probes[slot].id = n;
    g_probes[slot].uid = uid;
    g_probes[slot].node = "context";
    copy_bytes(g_probes[slot].query, sample, ACCESS_SAMPLE_MAX);

    a->local.data0 = 3;
    if (enter_clean_eval_scope()) {
        a->local.data3 = 1;
    } else {
        a->local.data0 = 0;
    }
}

static void after_sel_write_common(hook_fargs4_t *a, void *u)
{
    long live_ret;
    struct access_probe *probe;
    u32 id;
    u32 slot;

    if (!a->local.data0)
        return;

    id = (u32)a->local.data1;
    slot = (u32)a->local.data2;
    if (a->local.data3)
        leave_clean_eval_scope();

    probe = &g_probes[slot];
    if (probe->id != id)
        return;

    live_ret = (long)a->ret;

    /* Patch seqno in the access response buffer to match /sys/fs/selinux/status */
    if (live_ret > 0 && probe->node && probe->node[0] == 'a') {
        char *rbuf = (char *)a->arg1;
        ssize_t new_ret = patch_response_seqno(rbuf, live_ret, KP_AVD_CLEAN_SEQNO);
        if (new_ret > 0) {
            live_ret = new_ret;
            a->ret = (uint64_t)new_ret;
        }
    }

    selinux_hook_dbg("[selinux_hook] CLEAN /sys/fs/selinux/%s #%u uid=%d comm=%s clean_ret=%ld clean_policydb=%px blob=%px len=%zu query=\"%s\"\n",
                     probe->node ?: "?", id, probe->uid, current_comm(), live_ret,
                     READ_ONCE(g_clean_policydb), READ_ONCE(g_clean_policy_blob),
                     READ_ONCE(g_clean_policy_len), probe->query);
}

static int install_write_op_hooks(void)
{
    unsigned long addr_access, addr_context;
    hook_err_t hook_err;

    if (!clean_policydb_redirect_supported())
        return -EOPNOTSUPP;

    /* Direct symbols are required; no pointer-table fallback is available. */
    addr_access = (unsigned long)lookup_name_optional_suffix("sel_write_access");
    addr_context = (unsigned long)lookup_name_optional_suffix("sel_write_context");
    log_symbol_addr("sel_write_access", (void *)addr_access);
    log_symbol_addr("sel_write_context", (void *)addr_context);

    if (!addr_access) {
        pr_warn("[selinux_hook] sel_write_access unresolved; direct access/context hooks unavailable\n");
        return -EOPNOTSUPP;
    }

    if (g_hooks + (addr_context ? 2 : 1) >
        (int)(sizeof(g_funcs) / sizeof(g_funcs[0])))
        return -ENOSPC;

    pr_info("[selinux_hook] hook sel_write_access argc=3 mode=direct\n");
    hook_err = hook_wrap((void *)addr_access, 3, before_sel_write_access,
                         after_sel_write_common, NULL);
    if (hook_err != HOOK_NO_ERR) {
        pr_err("[selinux_hook] hook sel_write_access failed err=%d\n",
               (int)hook_err);
        return (int)hook_err;
    }
    record_inline_hook((void *)addr_access, before_sel_write_access,
                       after_sel_write_common);
    selinux_hook_dbg("[selinux_hook] inline hook sel_write_access @ %lx\n", addr_access);

    if (addr_context) {
        pr_info("[selinux_hook] hook sel_write_context argc=3 mode=direct\n");
        hook_err = hook_wrap((void *)addr_context, 3,
                             before_sel_write_context,
                             after_sel_write_common, NULL);
        if (hook_err != HOOK_NO_ERR) {
            pr_err("[selinux_hook] hook sel_write_context failed err=%d\n",
                   (int)hook_err);
            hook_unwrap((void *)addr_access, before_sel_write_access,
                        after_sel_write_common);
            g_hooks--;
            g_funcs[g_hooks] = NULL;
            g_hook_befores[g_hooks] = NULL;
            g_hook_afters[g_hooks] = NULL;
            return (int)hook_err;
        }
        record_inline_hook((void *)addr_context, before_sel_write_context,
                           after_sel_write_common);
        selinux_hook_dbg("[selinux_hook] inline hook sel_write_context @ %lx\n", addr_context);
    } else {
        pr_warn("[selinux_hook] sel_write_context not found, context hook skipped\n");
    }
    return 0;
}

static void record_inline_hook(void *func, void *before, void *after)
{
    g_funcs[g_hooks] = func;
    g_hook_befores[g_hooks] = before;
    g_hook_afters[g_hooks] = after;
    g_hooks++;
}

static void uninstall_inline_hooks(void)
{
    int i;

    for (i = 0; i < g_hooks; i++)
        hook_unwrap(g_funcs[i], g_hook_befores[i], g_hook_afters[i]);
    g_hooks = 0;
}

/* Hook: selinux_setprocattr(name, value, size) clean-policy wrapper */
static void before_selinux_setprocattr_clean_eval(hook_fargs3_t *a, void *u)
{
    const char *name = (const char *)a->arg0;
    uid_t uid = current_uid();
    u32 n;

    a->local.data0 = 0;

#if SELINUX_DIAG_TRACE
    a->local.data1 = diag_next();
    pr_info("[selinux_hook] DIAG setprocattr-IN #%llu uid=%d comm=%s name=%s size=%zu bypass=%d\n",
            (unsigned long long)a->local.data1, (int)uid, current_comm(),
            name ?: "(null)", (size_t)a->arg2,
            should_bypass_clean_filter(uid) ? 1 : 0);
#endif

    n = READ_ONCE(g_selinux_setprocattr_probe_count);
    if (n < 16) {
        n++;
        WRITE_ONCE(g_selinux_setprocattr_probe_count, n);
        pr_info("[selinux_hook] PROBE selinux_setprocattr #%u uid=%d comm=%s arg0=%px arg1=%px arg2=%zu\n",
                n, current_uid(), current_comm(), (void *)a->arg0,
                (void *)a->arg1, (size_t)a->arg2);
    }

    if (should_bypass_clean_filter(uid) || !str_eq_lit(name, "current"))
        return;

    /*
     * Do NOT enter a clean-eval scope here any more.
     *
     * Entering one made context_struct_compute_av() evaluate a live scontext
     * (the caller's current SID) against a tcontext parsed out of the clean
     * policydb.  That is exactly the call that killed the device at ~38.8 s in
     * every boot with the redirect enabled -- always immediately after the
     * first attr/current write from the Magisk manager -- while the same call
     * ran 11,606 times per boot without incident once the redirect was off.
     *
     * The clean policy's answer for these writes is simply "that context does
     * not exist", so return it directly, before the kernel parses or evaluates
     * anything.
     */
    if (names_privileged_context((const char *)a->arg1, (size_t)a->arg2)) {
        a->ret = (uint64_t)(long)-EINVAL;
        a->skip_origin = 1;
#if SELINUX_DIAG_TRACE
        pr_info("[selinux_hook] DIAG setprocattr-deny uid=%d comm=%s value=\"%.*s\"\n",
                (int)uid, current_comm(), (int)(size_t)a->arg2,
                (const char *)a->arg1);
#endif
    }
}

static void after_selinux_setprocattr_clean_eval(hook_fargs3_t *a, void *u)
{
    if (a->local.data0)
        leave_clean_eval_scope();
#if SELINUX_DIAG_TRACE
    pr_info("[selinux_hook] DIAG setprocattr-OUT #%llu ret=%ld scope=%d\n",
            (unsigned long long)a->local.data1, (long)a->ret,
            (int)a->local.data0);
#endif
}

/*
 * Return a clean backing page when an app opens /sys/fs/selinux/status.
 * sel_open_handle_status() stores selinux_kernel_status_page()'s return value
 * in filp->private_data, so redirecting the page factory covers both the read
 * and mmap paths without relying on any private structure offsets.
 */
static void before_selinux_kernel_status_page(hook_fargs4_t *a, void *u)
{
    void *page;

    if (should_bypass_clean_filter(current_uid()))
        return;

#if SELINUX_DIAG_TRACE
    pr_info("[selinux_hook] DIAG statuspage-IN uid=%d comm=%s\n",
            (int)current_uid(), current_comm());
#endif

    if (!g_fake_status_page || !vmalloc_to_page_fn)
        return;

    page = vmalloc_to_page_fn(g_fake_status_page);
    if (!page)
        return;

    a->ret = (uint64_t)page;
    a->skip_origin = 1;
}

static bool install_status_page_redirect(void)
{
    unsigned long addr;
    hook_err_t err;
    void *page;
    size_t fake_page_size = runtime_page_size();

    if (READ_ONCE(g_status_page_redirect_hooked))
        return true;

    if (!vmalloc_fn || !vmalloc_to_page_fn) {
        pr_warn("[selinux_hook] status page redirect unavailable vmalloc=%px vmalloc_to_page=%px\n",
                vmalloc_fn, vmalloc_to_page_fn);
        return false;
    }

    if (!g_fake_status_page) {
        g_fake_status_page = vmalloc_fn(fake_page_size);
        if (!g_fake_status_page) {
            pr_warn("[selinux_hook] fake status page allocation failed size=%zu\n",
                    fake_page_size);
            return false;
        }
        zero_bytes(g_fake_status_page, fake_page_size);
        copy_bytes(g_fake_status_page, g_clean_status_bytes,
                   sizeof(g_clean_status_bytes));
    }

    page = vmalloc_to_page_fn(g_fake_status_page);
    if (!page) {
        pr_warn("[selinux_hook] cannot translate fake status page to struct page\n");
        return false;
    }

    addr = (unsigned long)lookup_name_optional_suffix("selinux_kernel_status_page");
    if (!addr) {
        pr_warn("[selinux_hook] cannot find selinux_kernel_status_page\n");
        return false;
    }

    /* Both void(void) and stateful page-factory ABIs are safe through the
     * four-register transit: a state argument remains in x0 when present,
     * while a void function ignores it. */
    err = hook_wrap((void *)addr, 1, before_selinux_kernel_status_page,
                    NULL, NULL);
    if (err != HOOK_NO_ERR) {
        pr_warn("[selinux_hook] hook selinux_kernel_status_page failed err=%d\n",
                (int)err);
        return false;
    }

    record_inline_hook((void *)addr, before_selinux_kernel_status_page, NULL);
    WRITE_ONCE(g_status_page_redirect_hooked, true);
    pr_info("[selinux_hook] status page redirect installed factory=%px fake_page=%px backing=%px size=%zu\n",
            (void *)addr, g_fake_status_page, page, fake_page_size);
    return true;
}

static long init(const char *args, const char *event, void *__user r)
{
    unsigned long addr;
    int rc;

    selinux_hook_dbg("[selinux_hook] init event=%s\n", event ?: "(null)");

    /* Initialize clean status bytes based on kernel version */
    fill_clean_status_bytes(g_clean_status_bytes);
    selinux_hook_dbg("[selinux_hook] clean status: kver=%u.%u seq=%u pload=%u\n",
                     (unsigned)(kver >> 16), (unsigned)((kver >> 8) & 0xff),
                     get_u32_le(g_clean_status_bytes + 4),
                     get_u32_le(g_clean_status_bytes + 12));
    pr_info("[selinux_hook] kernel kver=%x legacy_blob_abi=%d\n",
            kver, use_legacy_clean_blob_query() ? 1 : 0);
    resolve_required_symbols_once();

    /* Raw spinlock helpers — kfunc wrappers are not exported on this kernel,
     * so resolve through kallsyms and call via function pointer.  The locks
     * become no-ops if resolution fails, which is acceptable for these
     * scope arrays (they only see per-task scope entry/exit pairs that
     * are also serialized against themselves). */
    g_raw_spin_lock_fn = (raw_spin_lock_fn_t)lookup_name_optional_suffix("_raw_spin_lock");
    g_raw_spin_unlock_fn = (raw_spin_unlock_fn_t)lookup_name_optional_suffix("_raw_spin_unlock");
    if (!g_raw_spin_lock_fn || !g_raw_spin_unlock_fn)
        pr_warn("[selinux_hook] raw_spin_lock/unlock unresolved: lock=%px unlock=%px; scope/cache lock will be a no-op\n",
                g_raw_spin_lock_fn, g_raw_spin_unlock_fn);

    copy_from_kernel_nofault_fn = (void *)lookup_name_optional_suffix("copy_from_kernel_nofault");
    if (!copy_from_kernel_nofault_fn)
        copy_from_kernel_nofault_fn = (void *)lookup_name_optional_suffix("probe_kernel_read");
    vmalloc_fn = (void *)lookup_name_optional_suffix("vmalloc");
    if (!vmalloc_fn)
        vmalloc_fn = (void *)lookup_name_optional_suffix("vmalloc_noprof");
    vmalloc_to_page_fn = (void *)lookup_name_optional_suffix("vmalloc_to_page");
    vfree_fn = (void *)lookup_name_optional_suffix("vfree");
    filp_open_fn = (void *)lookup_name_optional_suffix("filp_open");
    filp_close_fn = (void *)lookup_name_optional_suffix("filp_close");
    kernel_read_fn = (void *)lookup_name_optional_suffix("kernel_read");
    vfs_llseek_fn = (void *)lookup_name_optional_suffix("vfs_llseek");
    g_selinux_state = lookup_name_optional_suffix("selinux_state");
    if (!filp_open_fn || !filp_close_fn || !kernel_read_fn || !vfs_llseek_fn)
        pr_warn("[selinux_hook] cannot find file-read symbols: filp_open=%px filp_close=%px kernel_read=%px vfs_llseek=%px\n",
                filp_open_fn, filp_close_fn, kernel_read_fn, vfs_llseek_fn);
    security_load_policy_fn = (void *)lookup_name_optional_suffix("security_load_policy");
    security_context_to_sid_fn = (void *)lookup_name_optional_suffix("security_context_to_sid");
    security_context_to_sid_compat_fn = (void *)security_context_to_sid_fn;
    policydb_read_fn = (void *)lookup_name_optional_suffix("policydb_read");
    policydb_destroy_fn = (void *)lookup_name_optional_suffix("policydb_destroy");
    log_symbol_addr("selinux_state", g_selinux_state);
    log_symbol_addr("security_context_to_sid", (void *)security_context_to_sid_fn);
    log_symbol_addr("security_load_policy", (void *)security_load_policy_fn);
    log_symbol_addr("policydb_read", (void *)policydb_read_fn);
    log_symbol_addr("policydb_destroy", (void *)policydb_destroy_fn);
    pr_info("[selinux_hook] compat route: state_calls=%d policydb_redirect=%d\n",
            selinux_compat_call_needed() ? 1 : 0,
            clean_policydb_redirect_supported() ? 1 : 0);
    if (selinux_compat_call_needed())
        pr_info("[selinux_hook] SELinux compat calls enabled kver=%x state=%px\n",
                kver, g_selinux_state);
    /* Keep the clean policy snapshot available to redirect-capable hooks. */
    snapshot_clean_policy("module_init");
    if (!security_context_to_sid_fn)
        pr_warn("[selinux_hook] cannot find security_context_to_sid, procattr clean-policy redirect unavailable\n");
    if (!policydb_read_fn || !policydb_destroy_fn)
        pr_warn("[selinux_hook] cannot find policydb_read/policydb_destroy, clean policydb redirect disabled\n");
    bool status_page_redirect = false;
    status_page_redirect = install_status_page_redirect();
    if (status_page_redirect) pr_info("[selinux_hook] status page redirect successfully\n");
    else pr_warn("[selinux_hook] status page redirect failed\n");
    /* On failure, leave the kernel's native status mmap path untouched. */

    if (!security_load_policy_fn) {
        pr_warn("[selinux_hook] cannot find security_load_policy, deferred clean policy capture disabled\n");
    } else if (!READ_ONCE(g_clean_policy_blob)) {
        int argc = selinux_compat_call_needed() ? 4 : 3;

        record_inline_hook((void *)security_load_policy_fn,
                           before_security_load_policy,
                           after_security_load_policy);
        pr_info("[selinux_hook] hook security_load_policy argc=%d for deferred Magisk policy capture\n", argc);
        hook_wrap((void *)security_load_policy_fn, argc,
                  before_security_load_policy, after_security_load_policy, NULL);
    } else {
        selinux_hook_dbg("[selinux_hook] security_load_policy capture skipped; clean policy already loaded\n");
    }

    if (clean_policydb_redirect_supported()) {
        addr = (unsigned long)lookup_name_optional_suffix("selinux_setprocattr");
        if (addr) {
            record_inline_hook((void *)addr, before_selinux_setprocattr_clean_eval,
                               after_selinux_setprocattr_clean_eval);
            selinux_hook_dbg("[selinux_hook] hook selinux_setprocattr argc=3 clean-eval\n");
            hook_wrap((void *)addr, 3, before_selinux_setprocattr_clean_eval,
                      after_selinux_setprocattr_clean_eval, NULL);
        } else {
            pr_warn("[selinux_hook] cannot find selinux_setprocattr\n");
        }
    } else {
        selinux_hook_dbg("[selinux_hook] skip selinux_setprocattr clean-eval; policydb redirect unsupported\n");
    }

    if (clean_policydb_redirect_supported()) {
        rc = install_write_op_hooks();
        if (rc == -EOPNOTSUPP) {
            pr_warn("[selinux_hook] direct selinuxfs write hooks unavailable; continuing without access/context redirect\n");
        } else if (rc) {
            uninstall_inline_hooks();
            return rc;
        }
    } else {
        selinux_hook_dbg("[selinux_hook] skip /access and /context hooks; policydb redirect unsupported\n");
    }

    /* Policydb redirect hooks / policydb 重定向 hooks. */
	addr = (unsigned long)lookup_name_optional_suffix("context_struct_compute_av");
	if (!addr)
		addr = (unsigned long)lookup_name_numbered_suffix("context_struct_compute_av");
    if (addr && clean_policydb_redirect_supported()) {
        record_inline_hook((void *)addr, before_policydb_arg0, NULL);
        pr_info("[selinux_hook] hook context_struct_compute_av argc=6\n");
        hook_wrap((void *)addr, 6, before_policydb_arg0, NULL, NULL);
    } else if (!addr) {
        pr_warn("[selinux_hook] cannot find context_struct_compute_av\n");
    } else {
        selinux_hook_dbg("[selinux_hook] skip context_struct_compute_av; policydb redirect unsupported\n");
    }

    addr = (unsigned long)lookup_name_optional_suffix("string_to_context_struct");
    if (addr) {
        if (clean_policydb_redirect_supported()) {
            record_inline_hook((void *)addr, before_policydb_arg0, NULL);
            pr_info("[selinux_hook] hook string_to_context_struct argc=5\n");
            hook_wrap((void *)addr, 5, before_policydb_arg0, NULL, NULL);
        }
    } else {
        pr_warn("[selinux_hook] cannot find string_to_context_struct\n");
    }

    addr = (unsigned long)lookup_name_optional_suffix("selinux_complete_init");
    if (addr) {
        record_inline_hook((void *)addr, NULL, after_selinux_complete_init);
        pr_info("[selinux_hook] hook selinux_complete_init argc=0\n");
        hook_wrap((void *)addr, 0, NULL, after_selinux_complete_init, NULL);
    } else {
        pr_warn("[selinux_hook] cannot find selinux_complete_init\n");
    }

    addr = (unsigned long)lookup_name_optional_suffix("selinux_policy_commit");
    if (addr) {
        int argc = selinux_compat_call_needed() ? 2 : 1;

        record_inline_hook((void *)addr, NULL, after_selinux_policy_commit);
        pr_info("[selinux_hook] hook selinux_policy_commit argc=%d mode=%s\n",
                argc, selinux_compat_call_needed() ? "state+load_state" : "load_state");
        hook_wrap((void *)addr, argc, NULL, after_selinux_policy_commit, NULL);
    } else {
        pr_warn("[selinux_hook] cannot find selinux_policy_commit\n");
    }

    selinux_hook_dbg("[selinux_hook] %d hooks installed\n", g_hooks);

#if SELINUX_ASYNC_SNAPSHOT
    start_clean_snapshot_thread();
#endif

#if SELINUX_DIAG_WATCHDOG
    diag_watchdog_start();
#endif

    return 0;
}

static long exit_(void *__user r)
{
#if SELINUX_ASYNC_SNAPSHOT
    /* The snapshot thread runs code in module memory; stop it before unload. */
    WRITE_ONCE(g_snapshot_stop, true);
#endif
#if SELINUX_DIAG_WATCHDOG
    /* The watchdog thread lives in module memory; stop it before unload. */
    WRITE_ONCE(g_watchdog_stop, true);
    if (g_msleep_fn)
        g_msleep_fn(1000);
#endif
    uninstall_inline_hooks();

    /*
     * The fake page is returned through selinux_kernel_status_page() and may
     * still be referenced by already-open status files or VMAs.  Freeing it
     * here prevents a persistent vmalloc leak, but deliberately accepts the
     * resulting stale-reference/UAF risk during module unload.
     */
    if (g_fake_status_page) {
        pr_warn("[selinux_hook] UNSAFE: forcing fake SELinux status page free at exit; stale file/VMA references may cause UAF or a kernel crash\n");
        if (vfree_fn) {
            vfree_fn(g_fake_status_page);
            g_fake_status_page = NULL;
            WRITE_ONCE(g_status_page_redirect_hooked, false);
        } else {
            pr_err("[selinux_hook] cannot free fake SELinux status page: vfree is unavailable; vmalloc memory remains allocated\n");
        }
    }

    g_policy_capture_in_progress = false;

    if (READ_ONCE(g_clean_policydb_direct) && g_clean_policydb) {
        if (policydb_destroy_fn)
            policydb_destroy_fn((struct policydb *)g_clean_policydb);
        if (vfree_fn)
            vfree_fn(g_clean_policydb);
        g_clean_policydb = NULL;
        g_clean_policydb_direct = false;
    }

    if (g_clean_policy_blob) {
        if (vfree_fn)
            vfree_fn(g_clean_policy_blob);
        g_clean_policy_blob = NULL;
        g_clean_policy_len = 0;
    }

    selinux_hook_dbg("[selinux_hook] exited\n");
    return 0;
}

static sel_hook_state_t module_get_working_mode(void) // Used to identify the working mode
{
    bool redirect_supported = clean_policydb_redirect_supported();
    bool has_clean_policydb = READ_ONCE(g_clean_policydb) != NULL;

    if (!redirect_supported)
        return SEL_HOOK_STATE_UNSUPORRT;
    if (!has_clean_policydb)
        return SEL_HOOK_STATE_POLICYDB_REQ;
    return SEL_HOOK_STATE_NORMAL;
}

static long control(const char* args, char* __user out_msg, int outlen)
{
    sel_hook_state_t state;
    const char *state_str;
    int copied;
    size_t len;

    if (!args || !out_msg || outlen <= 0)
        return -EINVAL;

    if (str_eq_lit(args, "mode")) {
        state = module_get_working_mode();
        switch (state) {
        case SEL_HOOK_STATE_NORMAL:
            state_str = "NORMAL";
            break;
        case SEL_HOOK_STATE_POLICYDB_REQ:
            state_str = "POLICYDB_REQ";
            break;
        case SEL_HOOK_STATE_UNSUPORRT:
            state_str = "UNSUPORRT";
            break;
        default:
            state_str = "UNKNOWN";
            break;
        }

        len = str_len_safe(state_str);
        if (outlen < len)
            return -EINVAL;
        
        copied = compat_copy_to_user(out_msg, state_str, (int)len);
        if (copied != (int)len)
            return -EFAULT;
        
        return 0;
    }
    
    return -EINVAL;
}

KPM_INIT(init);
KPM_CTL0(control);
KPM_EXIT(exit_);
