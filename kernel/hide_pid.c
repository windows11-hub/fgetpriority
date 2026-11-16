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
 * hide_pid.c - hide one or more userspace processes from every path that
 * turns a pid number into a task, from /proc/<pid>, and from the /proc
 * directory listing itself.
 *
 * Only processes whose comm matches hide_comm_list (default "ksud", the
 * temporary root daemon) are hidden.
 *
 * Deliberately NOT hidden: zygote. An earlier revision also matched a zygote
 * whose pid was above 5000 after a soft restart, and that bricked every app
 * because the pid filter denies /proc/<pid>, kill/waitid and all pid -> task
 * lookups - zygote is the root of the Android process tree and must stay
 * resolvable. The soft-restart / temporary-root signal is addressed in
 * hide_self.c by spoofing getppid() and the PPid/Seccomp fields instead.
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
 *    returns 0. getpriority(PRIO_USER, uid), the channel the 春秋 detector uses
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
#include <linux/list.h>
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

/*
 * Hard ceiling on the tracked set. The snapshot is sized to the match count,
 * and a match count is only bounded by the number of processes on the device.
 * A runaway match (a broad comm, a fork storm) would ask kzalloc for an
 * arbitrarily large block on every rescan. Clamping keeps the cost predictable
 * and still covers every realistic case; a truncated set only means the extra
 * pids stay visible for one more scan.
 */
#define HIDE_MAX_TARGETS	256

/*
 * Fail safe, not fail open onto the device's throat.
 *
 * An empty list hides nothing, so a plain insmod arms the hooks but changes
 * no behaviour. Hiding something is always an explicit act, which means a
 * typo or a default can never be the thing that breaks a boot. service.sh
 * passes hide_comm_list=ksud explicitly.
 */
static char *hide_comm_list = "";
module_param(hide_comm_list, charp, 0444);
MODULE_PARM_DESC(hide_comm_list, "comma separated comm names to hide (empty = hide nothing)");

/*
 * Rescan interval. The default used to be 1000ms, but a full task-list walk
 * plus a snapshot allocation every second is a constant source of jitter on
 * fork() and /proc reads - exactly what makes MT Manager and Settings open
 * slowly. ksud is a fixed boot daemon whose pid only changes when it is
 * restarted, which is rare; 30s is plenty, and the kprobe path still filters
 * instantly in between rescans.
 */
static int hide_scan_ms = 30000;
module_param(hide_scan_ms, int, 0444);
MODULE_PARM_DESC(hide_scan_ms, "rescan interval in ms used to re-locate the target, 0 disables rescan");

static int hide_only_from_app = 1;
module_param(hide_only_from_app, int, 0444);
MODULE_PARM_DESC(hide_only_from_app, "1 = only hide from app-uid callers, 0 = hide from every caller");

static int hide_module_hide = 1;
module_param(hide_module_hide, int, 0444);
MODULE_PARM_DESC(hide_module_hide, "1 = remove this module from the kernel module list (default 1)");


/* ------------------------------------------------------------------------ */
/* published target state                                                   */
/* ------------------------------------------------------------------------ */

/*
 * ksud is not one process: the daemon stays up, and every "ksud ..." command
 * line is a second "ksud" that lives for milliseconds. Tracking a single pid
 * would latch onto a transient client, publish it, and then lose the daemon
 * when that client exits - the filter would flap and the daemon would be
 * visible again for a whole scan interval.
 *
 * The hidden set is published as one immutable snapshot behind an RCU pointer,
 * sized to exactly the number of targets found on the last scan, so there is
 * no fixed cap: a soft restart that leaves several same-comm "ksud"
 * processes behind all get hidden. Readers run in kprobe context where they
 * cannot sleep or take a lock, so they only rcu_read_lock() and
 * rcu_dereference() the pointer - which is precisely what RCU is for. A writer
 * allocates a fresh snapshot, swaps the pointer, and frees the old one through
 * call_rcu().
 */
struct hide_snapshot {
	struct rcu_head rcu;
	int count;
	pid_t pids[];
};

static struct hide_snapshot __rcu *hide_snap;

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
	struct hide_snapshot *s;
	bool hit = false;
	int i;

	if (nr <= 0)
		return false;

	/*
	 * A NULL snapshot means nothing is hidden (hide_comm_list empty or the
	 * scan found nothing), which is the common case on a healthy device.
	 * Taking rcu_read_lock() for that is pure overhead on the hottest
	 * pid-lookup path, so read the pointer once first and bail before the
	 * lock. A torn read here is harmless: a snapshot that appears or
	 * disappears between the check and the locked read is re-checked below.
	 */
	s = rcu_dereference(hide_snap);
	if (likely(!s))
		return false;

	rcu_read_lock();
	s = rcu_dereference(hide_snap);
	if (s) {
		for (i = 0; i < s->count; i++) {
			if (s->pids[i] == nr) {
				hit = true;
				break;
			}
		}
	}
	rcu_read_unlock();

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
 * nr is a number in namespace @ns, so it is only comparable to the published
 * snapshot when @ns is the initial namespace. NULL is treated as "not the
 * initial one".
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

/*
 * Processes the framework cannot lose sight of. Hiding any of these denies
 * /proc/<pid>, kill/waitid and every pid -> task lookup for it, which breaks
 * process management device-wide - hiding zygote or system_server means no
 * app can start at all. This list is a safety interlock: it applies even when
 * hide_comm_list is configured badly, so a typo cannot brick the device.
 */
static bool hide_is_critical_comm(const char *comm)
{
	static const char *const critical[] = {
		"init", "zygote", "zygote64", "zygote32",
		"usap32", "usap64", "system_server", "surfaceflinger",
	};
	int i;

	if (!comm)
		return true;	/* unknown: refuse rather than risk it */

	for (i = 0; i < (int)ARRAY_SIZE(critical); i++) {
		if (!strcmp(comm, critical[i]))
			return true;
	}

	/* prefix check on the stem so a future rename (zygote64_x, usap32x)
	 * cannot slip past the exact list above */
	if (!strncmp(comm, "zygote", 6) || !strncmp(comm, "usap", 4))
		return true;

	return false;
}

static bool hide_comm_is_target(const char *comm)
{
	const char *p = hide_comm_list;

	if (!p || !p[0] || !comm)
		return false;

	/* interlock: never match a process the system depends on */
	if (hide_is_critical_comm(comm))
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
 * NEVER hide a process the rest of the system depends on.
 *
 * The pid filter answers "no such process" to every caller that passes
 * hide_caller_filtered(), which includes /proc/<pid>, kill/waitid, stat and
 * every pid -> task lookup. That is fine for a root daemon nothing else
 * tracks, but zygote is the root of the whole Android process tree: apps are
 * forked from it and system_server has to keep resolving and waiting on
 * those pids. Hiding zygote breaks process management and no app can start.
 *
 * An earlier revision also matched a "zygote above hide_zygote_pid_limit"
 * (the soft-restart / temporary-root case) and that is exactly what made
 * every app unlaunchable. The zygote side of the temporary-root signal is
 * handled in hide_self.c by spoofing getppid() and /proc/self/status; the
 * process itself must stay fully visible.
 */
static bool hide_task_is_target(struct task_struct *p, pid_t nr)
{
	/*
	 * Only user processes with an address space. A kernel thread has no mm and
	 * hiding one (kworker, kthreadd, anything a broad comm match could catch)
	 * makes workqueue / scheduler bookkeeping lose the task, which panics the
	 * device rather than merely breaking an app. This is a structural check,
	 * not a name list, so it cannot be defeated by an unexpected comm.
	 */
	if (!p->mm)
		return false;

	/* only processes whose comm matches hide_comm_list (default "ksud") */
	if (hide_comm_is_target(p->comm))
		return true;

	return false;
}

/*
 * Called from process context only (module init and the delayed work), never
 * from a kprobe handler, so it may walk the task list under RCU and allocate.
 * No task reference is taken on purpose: put_task_struct() is not something a
 * module can rely on being reachable, and every value read here (comm, pid
 * number) is stable for as long as RCU holds the task alive.
 *
 * Two passes: first count the matching group leaders, then fill a snapshot of
 * exactly that size. Returns NULL on allocation failure, in which case the
 * previous snapshot stays in force.
 */
static struct hide_snapshot *hide_collect(void)
{
	struct task_struct *init = (struct task_struct *)kaddr_init_task;
	struct task_struct *p;
	struct hide_snapshot *s;
	int total = 0, n = 0;

	if (!init)
		return NULL;

	/* pass 1: count matching group leaders, bounded by the hard ceiling */
	rcu_read_lock();
	list_for_each_entry_rcu(p, &init->tasks, tasks) {
		if (p->group_leader != p)
			continue;
		if (!hide_task_is_target(p, (pid_t)task_pid_nr(p)))
			continue;
		total++;
		if (total >= HIDE_MAX_TARGETS)
			break;
	}
	rcu_read_unlock();

	s = kzalloc(sizeof(*s) + sizeof(pid_t) * (size_t)total, GFP_KERNEL);
	if (!s)
		return NULL;
	s->count = total;

	if (!total)
		return s;

	/* pass 2: fill.
	 *
	 * The task list is live: between the count pass and this one a process
	 * may have appeared (a new "ksud ..." client, or a target forked after
	 * a respawn), which would push n past the size allocated in pass 1 and
	 * write out of bounds. Stop at the allocated capacity and record what
	 * actually fit; the next rescan picks up the rest. */
	rcu_read_lock();
	list_for_each_entry_rcu(p, &init->tasks, tasks) {
		pid_t nr;

		if (p->group_leader != p)
			continue;
		nr = (pid_t)task_pid_nr(p);
		if (!hide_task_is_target(p, nr))
			continue;
		if (n >= total)
			break;
		s->pids[n++] = nr;
	}
	rcu_read_unlock();

	s->count = n;

	return s;
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

static void hide_snapshot_free_rcu(struct rcu_head *head)
{
	struct hide_snapshot *s = container_of(head, struct hide_snapshot, rcu);

	kfree(s);
}

static void hide_publish(struct hide_snapshot *s)
{
	struct hide_snapshot *old;

	old = rcu_dereference_protected(hide_snap, 1);
	rcu_assign_pointer(hide_snap, s);

	if (old)
		call_rcu(&old->rcu, hide_snapshot_free_rcu);
}

static void hide_refresh(void)
{
	struct hide_snapshot *s, *cur;
	int i;

	s = hide_collect();
	if (!s)
		return;	/* allocation failed: keep the previous snapshot */

	/* only the writer replaces the pointer, and this runs from the same
	 * process-context path that calls hide_publish(), so comparing against
	 * the current snapshot needs no reader protection here. */
	cur = rcu_dereference_protected(hide_snap, 1);
	if (cur && s->count == cur->count &&
	    hide_set_equal(s->pids, s->count, cur->pids, cur->count)) {
		kfree(s);
		return;
	}

	if (!s->count) {
		hide_publish(s);
		pr_info("hide_pid: no target left, filter idle\n");
		return;
	}

	pr_info("hide_pid: hiding %d pid(s)\n", s->count);
	for (i = 0; i < s->count; i++)
		pr_info("hide_pid:   pid %d\n", (int)s->pids[i]);

	hide_publish(s);
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
	int nr;

	if (!hide_caller_filtered())
		return 0;

	nr = (int)PT_REGS_PARM1(regs);

	if (hide_ns_matches(nr, (struct pid_namespace *)PT_REGS_PARM2(regs)))
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
	int nr;

	if (!hide_caller_filtered())
		return 0;

	nr = (int)PT_REGS_PARM1(regs);

	if (hide_ns_matches(nr, (struct pid_namespace *)PT_REGS_PARM2(regs)))
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
 * Pull the module out of the kernel's module list.
 *
 * This is the only thing that actually removes it from what a userspace
 * detector can reach. Renaming was not enough and neither is unlinking
 * /sys/module: both leave /proc/modules enumerating modules via
 * list_for_each_entry(&modules), so the entry is still there under whatever
 * name we set - and a module list that does not match the kernel's own
 * bookkeeping is itself a signal.
 *
 * After list_del the module is invisible to every reader of that list:
 * /proc/modules, /sys/module iteration, and the module walk behind
 * kallsyms' module symbol lookup. The struct stays alive because we hold our
 * own reference implicitly by still running from it, and nothing else needs
 * the list linkage while the module is loaded.
 *
 * Cost: rmmod can no longer find it by name. Unloading afterwards needs
 * rmmod -f with the address, or a reboot. That is the trade for actually
 * being absent from the list rather than masquerading in it.
 */
static bool hide_module_unlinked;
/*
 * Reinsertion needs the *original* neighbours, so they are recorded before the
 * unlink. list_add(&m->list, &m->list) would not restore anything - it links
 * the node to itself, which corrupts the list on the next walk.
 */
static struct list_head *hide_prev;
static struct list_head *hide_next;

static void hide_module_unlink(void)
{
	if (!hide_module_hide)
		return;

	if (hide_module_unlinked)
		return;

	/*
	 * Only safe once the module is fully live: pulling the list node during
	 * init races every concurrent reader that is walking modules. Called at
	 * the end of fgetpriority_init(), after every hook is registered.
	 *
	 * Remember the neighbours first so hide_module_relink() can put the node
	 * back in its original position rather than corrupting the list.
	 */
	hide_prev = THIS_MODULE->list.prev;
	hide_next = THIS_MODULE->list.next;
	list_del_init(&THIS_MODULE->list);
	hide_module_unlinked = true;

	pr_info("hide_pid: module removed from the module list\n");
}

static void hide_module_relink(void)
{
	if (!hide_module_unlinked)
		return;

	/* splice the node back between its recorded neighbours */
	hide_prev->next = &THIS_MODULE->list;
	hide_next->prev = &THIS_MODULE->list;
	THIS_MODULE->list.prev = hide_prev;
	THIS_MODULE->list.next = hide_next;

	hide_module_unlinked = false;
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
	struct hide_snapshot *cur;
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

	/*
	 * The three pid-lookup kprobes exist ONLY to hide hide_comm_list. They sit
	 * on find_pid_ns / find_task_by_pid_ns / find_ge_pid, which are among the
	 * hottest functions in the kernel - every kill, waitid and /proc open
	 * traps through them. With an empty hide_comm_list there is nothing to
	 * hide, so registering them only burns a BRK trap on the hottest path and
	 * makes apps open slowly for no gain. Skip them entirely when no target
	 * is configured. Module-list hiding (hide_module_unlink) is separate and
	 * is still done by main.c.
	 */
	if (hide_comm_list && hide_comm_list[0]) {
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
	} else {
		pr_info("hide_pid: hide_comm_list empty, pid-lookup kprobes not armed\n");
	}

	/*
	 * The module is NOT unlinked here. hide_pid_init() runs early in
	 * fgetpriority_init(), before hide_self_init(), and pulling the list node
	 * while the rest of init is still touching THIS_MODULE races every reader
	 * walking the module list. fgetpriority_init() calls hide_module_unlink()
	 * as its very last act instead.
	 */

	/*
	 * Publish and schedule the rescan only when something is actually hidden.
	 * With an empty comm list the snapshot walk and the periodic rescan are
	 * pure overhead (a full task-list traversal + allocation on a timer).
	 */
	if (hide_comm_list && hide_comm_list[0]) {
		hide_refresh();
		cur = rcu_dereference_protected(hide_snap, 1);
		if (!cur || !cur->count)
			pr_info("hide_pid: no '%s' process yet, will keep scanning\n",
				hide_comm_list);

		if (hide_scan_ms > 0) {
			hide_scan_period = hide_scan_ms;
			INIT_DELAYED_WORK(&hide_scan_work, hide_scan_fn);
			schedule_delayed_work(&hide_scan_work,
					      msecs_to_jiffies((unsigned int)hide_scan_period));
			pr_info("hide_pid: rescan every %dms\n", hide_scan_period);
		}
	} else {
		cur = NULL;
	}

	pr_info("hide_pid: %d hook(s) armed, %d pid(s) hidden\n",
		armed, cur ? cur->count : 0);
	if (cur)
		for (i = 0; i < cur->count; i++)
			pr_info("hide_pid:   pid %d\n", (int)cur->pids[i]);

	/* empty comm list is not an error: nothing to hide, and no hooks were
	 * armed (they are deliberately skipped to keep the hot path clean) */
	if (hide_comm_list && hide_comm_list[0])
		return armed ? 0 : -ENODEV;
	return 0;
}

static void hide_pid_exit(void)
{
	struct hide_snapshot *s;

	if (hide_scan_period > 0) {
		hide_scan_period = 0;
		cancel_delayed_work_sync(&hide_scan_work);
	}

	destroy_kprobe(&kp_find_pid_ns);
	destroy_kprobe(&kp_find_task_by_pid_ns);
	destroy_kprobe(&kp_find_ge_pid);

	/*
	 * The final snapshot is freed here, but hide_publish() may still have
	 * call_rcu(&old->rcu, hide_snapshot_free_rcu) pending, and that callback
	 * lives in module text. Unloading the module with a callback still queued
	 * is a use-after-free of freed kernel text on the next grace period:
	 * an immediate panic, not a graceful failure.
	 *
	 * synchronize_rcu() only waits for readers, it does NOT run callbacks.
	 * rcu_barrier() is the primitive that also drains the queued callbacks,
	 * so nothing can execute this module's code after return.
	 */
	s = rcu_dereference_protected(hide_snap, 1);
	rcu_assign_pointer(hide_snap, NULL);
	rcu_barrier();
	kfree(s);
}
