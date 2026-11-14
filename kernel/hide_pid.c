// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 \xx
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
/*
 * hide_pid.c - hide one userspace process (default: "ksud") from every path
 * that turns a pid number into a task, from /proc/<pid>, and from the /proc
 * directory listing itself.
 *
 * Unity built: main.c includes this file after arch.h, routine.h and
 * routine_kp.c, so PT_REGS_*, init_kprobe()/destroy_kprobe(), the
 * kallsyms_lookup_name() override and MIN_APP_PROCESS_UID are all in scope.
 * It is NOT a standalone translation unit and must stay below those includes.
 *
 * ===========================================================================
 * 1. WHERE A PID TURNS INTO A TASK
 *
 * Every syscall that accepts a pid ends up in one of these kernel/pid.c
 * primitives:
 *
 *     struct pid *find_pid_ns(int nr, struct pid_namespace *ns)
 *             return idr_find(&ns->idr, nr);
 *
 *     struct task_struct *find_task_by_pid_ns(int nr, struct pid_namespace *ns)
 *             return pid_task(find_pid_ns(nr, ns), PIDTYPE_PID);
 *
 *     struct pid *find_ge_pid(int nr, struct pid_namespace *ns)
 *             smallest existing pid >= nr, used to walk /proc
 *
 * The two wrapper functions the syscalls actually call are find_vpid() and
 * find_task_by_vpid(); both are thin inlines over find_pid_ns() and
 * find_task_by_pid_ns() respectively. So three kprobes cover everything:
 *
 *   find_pid_ns            kill, tkill, tgkill, rt_sigqueueinfo,
 *                          rt_tgsigqueueinfo, pidfd_open, pidfd_getfd, waitid
 *   find_task_by_pid_ns    sched_{get,set}{affinity,param,scheduler,attr},
 *                          getpriority, setpriority, ioprio_{get,set},
 *                          getpgid, getsid, prlimit64, get_robust_list,
 *                          set_robust_list, ptrace, kcmp, migrate_pages,
 *                          move_pages, process_vm_readv, process_vm_writev,
 *                          getrusage(who), setns, and /proc/<pid> itself
 *   find_ge_pid            the readdir("/proc") iterator (next_tgid)
 *
 * Patching individual syscall entry points instead (what routine_raw.c does
 * for find_user) is not viable here: dozens of syscalls take a pid and that
 * list moves between kernel versions.
 *
 * ===========================================================================
 * 2. WHY A KPROBE RATHER THAN A BRANCH PATCH
 *
 * Rewriting the first instruction of find_pid_ns with "b hook" would need the
 * hook within +/-128MB of core kernel text (routine_raw.c already bails with
 * -ERANGE past that), would destroy the "bti c" landing pad GKI requires for
 * indirect calls, and would race ftrace over the patchable prologue. A kprobe
 * swaps one instruction through text_poke(), is always reachable and reverts
 * cleanly. GKI ships CONFIG_KPROBES=y.
 *
 * A pre_handler cannot synthesise a return value, so it rewrites the
 * *argument*: nr becomes a value above PID_MAX_LIMIT that can never exist in
 * the idr, the real function then misses its own lookup and returns NULL.
 * Callers see a plain "no such process". Same trick routine_kp.c plays with
 * the uid.
 *
 * ===========================================================================
 * 3. WHY find_ge_pid IS HOOKED TOO
 *
 * Hooking only the two resolvers leaves an inconsistency worse than the
 * original problem: readdir("/proc") would still emit ksud's number, and
 * every attempt to stat()/open() that entry would fail with ENOENT. "Listed
 * by readdir but never resolvable" is a far stronger anomaly signal than a
 * perfectly ordinary process the detector can see. So the iterator is hooked
 * as well: when it asks for the hidden number, it is bumped to the next one
 * and the entry never appears. /proc becomes internally consistent - the
 * process is simply not there.
 *
 * ===========================================================================
 * 4. WHAT A DETECTOR SEES ONCE THIS IS ARMED
 *
 *     kill(ksud, 0) / tgkill(ksud, ...)       -> -1 ESRCH
 *     pidfd_open(ksud, 0)                     -> -1 ESRCH
 *     sched_getaffinity(ksud, ...)            -> -1 ESRCH
 *     getpriority(PRIO_PROCESS, ksud)         -> -1 ESRCH
 *     ptrace(PTRACE_ATTACH, ksud)             -> -1 ESRCH
 *     process_vm_readv(ksud, ...)             -> -1 ESRCH
 *     stat("/proc/<ksud>")                    -> -1 ENOENT
 *     open("/proc/<ksud>/cmdline")            -> -1 ENOENT
 *     readdir("/proc")                        -> ksud's number is absent
 *
 * ===========================================================================
 * 5. WHO IS FILTERED (hide_only_from_app)
 *
 * By default the filter only applies to callers that look like a sandboxed
 * app: uid >= MIN_APP_PROCESS_UID and TIF_SECCOMP set (zygote installs a
 * seccomp filter into every app). Root, init, system_server and kernel
 * threads keep the true view, so "ps" from adb shell, ActivityManager's own
 * bookkeeping and this module's service.sh all keep working. Set
 * hide_only_from_app=0 to hide the pid from every caller, which is stronger
 * but also blinds your own tooling.
 *
 * ===========================================================================
 * 6. SOFT REBOOT
 *
 * A soft reboot (zygote or system_server restart - the kernel stays up) gives
 * ksud a brand new pid while the hooks remain armed. The hooks never cache a
 * task, only compare against the published pid set, and a delayed work item
 * walks init_task.tasks every hide_scan_ms milliseconds collecting every
 * group leader whose comm matches hide_comm_list. The set is republished
 * through a seqlock, so a handler sees either the whole old set or the whole
 * new one. The exposure window after a respawn is therefore at most one scan
 * interval (default 1000ms; hide_scan_ms=0 disables rescanning).
 *
 * The set matters: every "ksud ..." command line is a second process with the
 * same comm that lives for milliseconds. Tracking a single pid would latch
 * onto such a client and then lose the daemon when that client exits.
 *
 * If no process matches any more the set is emptied, so a recycled pid number
 * belonging to an unrelated process is never hidden.
 *
 * ===========================================================================
 * 7. KNOWN GAPS (by design, not bugs)
 *
 *  - Table-wide walks that never name a pid are untouched: kill(-1, 0) still
 *    returns 0. getpriority(PRIO_USER, uid), the channel the 鏄ョ detector uses
 *    for its "hidden app list" check, is already handled by routine_raw.c.
 *  - Thread ids are not filtered; the match key is the group leader pid, which
 *    is what task_pid_nr()/ps show.
 *  - A nested pid namespace (container) numbers pids differently; the filter
 *    only matches ns->level == 0, so it does not apply there.
 *  - Anything that resolved /proc/<pid>/... before the module was loaded keeps
 *    that already-open reference. Nothing can retroactively take it away.
 *  - hide_only_from_app uses uid >= 10000. A detector running as a plain
 *    foreground shell (uid 2000) is not filtered.
 *
 * ===========================================================================
 * 8. RISK: these are warm code paths
 *
 * find_pid_ns() and find_task_by_pid_ns() are on a large fraction of syscalls,
 * and each matching hit costs a trap into the kprobe handler. The handler
 * itself is three comparisons, but the trap is real. If the regression
 * matters more than the coverage, keep only find_task_by_pid_ns (covers
 * /proc and the sched_* and priority families) and drop the other two.
 */

#include <asm/barrier.h>

#include <linux/cache.h>
#include <linux/cred.h>
#include <linux/jiffies.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/sched.h>
#include <linux/workqueue.h>

/* above PID_MAX_LIMIT (4 * 1024 * 1024), so any idr lookup is guaranteed to miss */
#define HIDE_ABSENT_PID		0x40000000

/*
 * hide_refresh() walks the full task list, so an absurdly small interval would
 * burn CPU on a device with hundreds of processes. Anything below this is
 * clamped rather than honoured.
 */
#define HIDE_SCAN_MIN_MS	250

static char *hide_comm_list = "ksud";
module_param(hide_comm_list, charp, 0444);
MODULE_PARM_DESC(hide_comm_list, "comma separated comm names to hide (default: ksud)");

static int hide_scan_ms = 1000;
module_param(hide_scan_ms, int, 0444);
MODULE_PARM_DESC(hide_scan_ms, "rescan interval in ms used to re-locate the target, 0 disables rescan");

static int hide_only_from_app = 1;
module_param(hide_only_from_app, int, 0444);
MODULE_PARM_DESC(hide_only_from_app, "1 = only hide from app-uid callers, 0 = hide from every caller");

static char *hide_module_name = "";
module_param(hide_module_name, charp, 0444);
MODULE_PARM_DESC(hide_module_name, "if set, report this name in /proc/modules instead of the real one");

/* ------------------------------------------------------------------------ */
/* published target state                                                   */
/* ------------------------------------------------------------------------ */

/*
 * ksud is not one process: the daemon stays up, and every "ksud ..." command
 * line is a second "ksud" that lives for milliseconds. Tracking a single pid
 * would latch onto a transient client, publish it, and then lose the daemon
 * when that client exits - the filter would flap and the daemon would be
 * visible again for a whole scan interval. So a small set is kept, published
 * as a whole.
 */
#define HIDE_MAX_TARGETS	8

static pid_t hide_pids[HIDE_MAX_TARGETS] __read_mostly;
static int hide_pid_count __read_mostly;
/*
 * Seqlock: odd while hide_publish() is writing the array. Readers run in
 * kprobe context, so they cannot take a lock; they fail open on a torn or
 * in-progress read. A callback that answers "not hidden" for one syscall is
 * harmless, one that hid an unrelated pid number would not be.
 */
static unsigned int hide_seq __read_mostly;

static struct delayed_work hide_scan_work;
static int hide_scan_period;

static uintptr_t kaddr_init_task;

static struct kprobe *kp_find_pid_ns;
static struct kprobe *kp_find_task_by_pid_ns;
static struct kprobe *kp_find_ge_pid;

/* ------------------------------------------------------------------------ */
/* match helpers - all of these run in kprobe context                       */
/* ------------------------------------------------------------------------ */

static __always_inline bool hide_pid_match(int nr)
{
	unsigned int seq;
	int i;
	bool hit = false;

	if (nr <= 0)
		return false;

	seq = smp_load_acquire(&hide_seq);
	if (seq & 1)
		return false;	/* publish in progress: stay out of the way */

	for (i = 0; i < HIDE_MAX_TARGETS && i < hide_pid_count; i++) {
		if (hide_pids[i] == nr) {
			hit = true;
			break;
		}
	}

	/* a publish we overlapped means the set we just read is not coherent */
	if (smp_load_acquire(&hide_seq) != seq)
		return false;

	return hit;
}

/*
 * Keep root and system services seeing the truth, otherwise "ps" from adb,
 * ActivityManager's process bookkeeping and our own service.sh break.
 */
static __always_inline bool hide_caller_filtered(void)
{
	if (!hide_only_from_app)
		return true;

	/* zygote installs a seccomp filter into every app process */
	if (!is_seccomp_enabled())
		return false;

	return current_uid().val >= MIN_APP_PROCESS_UID;
}

/*
 * nr is a number in namespace @ns, so it is only comparable to hide_pids[] when
 * @ns is the initial namespace. NULL is treated as "not the initial one".
 */
static __always_inline bool hide_ns_matches(int nr, struct pid_namespace *ns)
{
	if (!ns || ns->level != 0)
		return false;

	return hide_pid_match(nr);
}

/* ------------------------------------------------------------------------ */
/* target discovery                                                         */
/* ------------------------------------------------------------------------ */

static bool hide_comm_is_target(const char *comm)
{
	const char *p = hide_comm_list;

	if (!p || !p[0] || !comm)
		return false;

	while (p[0]) {
		const char *end = strchr(p, ',');
		int len = end ? (int)(end - p) : (int)strlen(p);

		if (len > 0 && len < TASK_COMM_LEN &&
		    !strncmp(p, comm, len) && comm[len] == '\0')
			return true;

		if (!end)
			break;
		p = end + 1;
	}

	return false;
}

/*
 * Called from process context only (module init and the delayed work), never
 * from a kprobe handler, so it may walk the task list under RCU. No task
 * reference is taken on purpose: put_task_struct() is not something a module
 * can rely on being reachable, and every value read here (comm, pid number) is
 * stable for as long as RCU holds the task alive.
 */
static void hide_collect(pid_t *out, int *count)
{
	struct task_struct *init = (struct task_struct *)kaddr_init_task;
	struct task_struct *p;
	int n = 0;

	*count = 0;
	if (!init)
		return;

	rcu_read_lock();
	list_for_each_entry_rcu(p, &init->tasks, tasks) {
		/* only group leaders: a "ksud" child thread must not be matched */
		if (p->group_leader != p)
			continue;
		if (!hide_comm_is_target(p->comm))
			continue;
		if (n >= HIDE_MAX_TARGETS)
			break;

		out[n++] = (pid_t)task_pid_nr(p);
	}
	rcu_read_unlock();

	*count = n;
}

static bool hide_set_equal(const pid_t *a, int an, const pid_t *b, int bn)
{
	int i, j;

	if (an != bn)
		return false;

	for (i = 0; i < an; i++) {
		for (j = 0; j < bn; j++)
			if (a[i] == b[j])
				break;
		if (j == bn)
			return false;
	}

	return true;
}

static void hide_publish(const pid_t *set, int count)
{
	unsigned int seq = smp_load_acquire(&hide_seq);
	int i;

	smp_store_release(&hide_seq, seq + 1);	/* odd: write in progress */
	smp_mb();

	for (i = 0; i < HIDE_MAX_TARGETS; i++)
		hide_pids[i] = i < count ? set[i] : 0;
	smp_store_release(&hide_pid_count, count);

	smp_store_release(&hide_seq, seq + 2);	/* even: stable again */
}

static void hide_refresh(void)
{
	pid_t now[HIDE_MAX_TARGETS];
	int count = 0;
	int i;

	hide_collect(now, &count);

	if (count == hide_pid_count && hide_set_equal(now, count, hide_pids, hide_pid_count))
		return;

	if (!count) {
		if (hide_pid_count) {
			hide_publish(now, 0);
			pr_info("hide_pid: no target left, filter idle\n");
		}
		return;
	}

	hide_publish(now, count);

	for (i = 0; i < count; i++)
		pr_info("hide_pid: hiding pid %d\n", (int)now[i]);
}

static void hide_scan_fn(struct work_struct *unused)
{
	hide_refresh();

	if (hide_scan_period > 0)
		schedule_delayed_work(&hide_scan_work,
				      msecs_to_jiffies((unsigned int)hide_scan_period));
}

/* ------------------------------------------------------------------------ */
/* kprobe handlers                                                          */
/* ------------------------------------------------------------------------ */

/*
 * struct pid *find_pid_ns(int nr, struct pid_namespace *ns)
 *
 *   return idr_find(&ns->idr, nr);
 *
 * An out-of-range nr makes the idr lookup miss, so the function returns NULL,
 * which is exactly its "no such pid" answer.
 */
static int kp_find_pid_ns_pre(struct kprobe *unused, struct pt_regs *regs)
{
	if (!hide_caller_filtered())
		return 0;

	if (hide_ns_matches((int)PT_REGS_PARM1(regs),
			    (struct pid_namespace *)PT_REGS_PARM2(regs)))
		PT_REGS_PARM1(regs) = HIDE_ABSENT_PID;

	return 0;
}

/*
 * struct task_struct *find_task_by_pid_ns(int nr, struct pid_namespace *ns)
 *
 *   return pid_task(find_pid_ns(nr, ns), PIDTYPE_PID);
 *
 * This is the gate /proc/<pid> uses (proc_pid_lookup -> find_task_by_pid_ns,
 * or find_vpid + get_pid_task on older trees; both are covered because
 * find_pid_ns is hooked as well).
 */
static int kp_find_task_by_pid_ns_pre(struct kprobe *unused, struct pt_regs *regs)
{
	if (!hide_caller_filtered())
		return 0;

	if (hide_ns_matches((int)PT_REGS_PARM1(regs),
			    (struct pid_namespace *)PT_REGS_PARM2(regs)))
		PT_REGS_PARM1(regs) = HIDE_ABSENT_PID;

	return 0;
}

/*
 * struct pid *find_ge_pid(int nr, struct pid_namespace *ns)
 *
 * Used by next_tgid() to produce the /proc directory listing. Bumping nr past
 * the hidden number makes the iterator skip it, so readdir("/proc") never
 * emits an entry that cannot be opened - which is what a detector would
 * notice far sooner than a missing process.
 */
static int kp_find_ge_pid_pre(struct kprobe *unused, struct pt_regs *regs)
{
	int nr = (int)PT_REGS_PARM1(regs);

	if (!hide_caller_filtered())
		return 0;

	if (hide_ns_matches(nr, (struct pid_namespace *)PT_REGS_PARM2(regs)))
		PT_REGS_PARM1(regs) = nr + 1;

	return 0;
}

/* ------------------------------------------------------------------------ */
/* optional: decoy name in /proc/modules                                    */
/* ------------------------------------------------------------------------ */

#ifdef MODULE
/*
 * /sys/module was already unlinked by fgetpriority_init(), but /proc/modules
 * still shows the real name. Overwriting module->name hides it, at the cost
 * that "rmmod fgetpriority" stops working and the decoy name has to be used
 * instead. Empty (disabled) by default.
 */
static void hide_module_rename(void)
{
	size_t len;

	if (!hide_module_name || !hide_module_name[0])
		return;

	len = strlen(hide_module_name);
	if (len >= sizeof(THIS_MODULE->name) - 1) {
		pr_info("hide_pid: decoy name too long, ignored\n");
		return;
	}

	memset(THIS_MODULE->name, 0, sizeof(THIS_MODULE->name));
	memcpy(THIS_MODULE->name, hide_module_name, len);

	pr_info("hide_pid: /proc/modules now reports '%s'\n", hide_module_name);
}
#endif

/* ------------------------------------------------------------------------ */
/* init / exit                                                              */
/* ------------------------------------------------------------------------ */

static __init int hide_arm(const char *sym, kprobe_pre_handler_t pre, struct kprobe **slot)
{
	if (!kallsyms_lookup_name(sym)) {
		pr_info("hide_pid: %s not in kallsyms, skipped\n", sym);
		return -ENOENT;
	}

	*slot = init_kprobe(sym, pre);
	if (!*slot)
		return -EAGAIN;

	return 0;
}

static __init int hide_pid_init(void)
{
	int armed = 0;
	int i;

	kaddr_init_task = kallsyms_lookup_name("init_task");
	if (!kaddr_init_task) {
		pr_info("hide_pid: init_task not in kallsyms, cannot track the target\n");
		return -ENOENT;
	}

	if (hide_scan_ms > 0 && hide_scan_ms < HIDE_SCAN_MIN_MS) {
		pr_info("hide_pid: hide_scan_ms=%d too small, clamped to %d\n",
			hide_scan_ms, HIDE_SCAN_MIN_MS);
		hide_scan_ms = HIDE_SCAN_MIN_MS;
	}

	if (!hide_arm("find_pid_ns", (kprobe_pre_handler_t)kp_find_pid_ns_pre,
		      &kp_find_pid_ns))
		armed++;

	if (!hide_arm("find_task_by_pid_ns",
		      (kprobe_pre_handler_t)kp_find_task_by_pid_ns_pre,
		      &kp_find_task_by_pid_ns))
		armed++;

	if (!hide_arm("find_ge_pid", (kprobe_pre_handler_t)kp_find_ge_pid_pre,
		      &kp_find_ge_pid))
		armed++;

#ifdef MODULE
	hide_module_rename();
#endif

	/*
	 * Publish before returning: does not matter whether the hooks or the set
	 * land first, an empty set simply hides nothing for that instant.
	 */
	hide_refresh();
	if (!hide_pid_count)
		pr_info("hide_pid: no '%s' process yet, will keep scanning\n",
			hide_comm_list);

	if (hide_scan_ms > 0) {
		hide_scan_period = hide_scan_ms;
		INIT_DELAYED_WORK(&hide_scan_work, hide_scan_fn);
		schedule_delayed_work(&hide_scan_work,
				      msecs_to_jiffies((unsigned int)hide_scan_period));
		pr_info("hide_pid: rescan every %dms\n", hide_scan_period);
	}

	pr_info("hide_pid: %d hook(s) armed, %d pid(s) hidden\n",
		armed, hide_pid_count);
	for (i = 0; i < hide_pid_count; i++)
		pr_info("hide_pid:   pid %d\n", (int)hide_pids[i]);

	return armed ? 0 : -ENODEV;
}

static void hide_pid_exit(void)
{
	if (hide_scan_period > 0) {
		hide_scan_period = 0;
		cancel_delayed_work_sync(&hide_scan_work);
	}

	destroy_kprobe(&kp_find_pid_ns);
	destroy_kprobe(&kp_find_task_by_pid_ns);
	destroy_kprobe(&kp_find_ge_pid);

	hide_publish(hide_pids, 0);
}
