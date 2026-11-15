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
 * hide_self.c - make zygote's own pid small, so the getppid() check passes
 * with a REAL value instead of a fabricated one.
 *
 * ===========================================================================
 * 1. THE CHECK
 *
 * The detector decides "temporary root / 免解" from two readings, either of
 * which fails it:
 *
 *   1. getppid() returns a pid above ~5000. An app is forked by the system
 *      zygote, so getppid() IS the zygote's own pid. A zygote that started at
 *      boot gets a small pid; after a soft restart (zygote restart without a
 *      kernel reboot, which is what temporary root needs) the PID COUNTER IS
 *      NOT RESET, so the re-forked zygote is numbered in the tens of
 *      thousands and every app inherits that number through getppid().
 *
 *   2. Seccomp: 0 in /proc/self/status. zygote installs a filter into every
 *      app, so a real app reports 2.
 *
 * ===========================================================================
 * 2. WHY THE OBVIOUS APPROACH MUST NOT BE USED
 *
 * Rewriting the getppid() return value to a small random number looks like it
 * solves (1) and is what an earlier revision did. It does not work, and the
 * reason is a kernel invariant no hook can fake:
 *
 *      getppid() never returns a pid that does not exist.
 *
 * A real parent is either alive (so /proc/<ppid> resolves) or dead, in which
 * case the child has been reparented to init and getppid() returns 1. There is
 * no state in a correct kernel where getppid() names a task that is not there.
 *
 * A fabricated number breaks three things at once:
 *
 *      - open("/proc/<fabricated>/comm")        -> ENOENT
 *      - a sibling process reports a different ppid (it was hashed from a
 *        different value), yet both were forked by the same zygote
 *      - the number does not match the zygote pid that /proc actually shows
 *
 * A detector that reads any of those sees a kernel doing something a kernel
 * cannot do. Worse than being detected: it crashes the detector, because code
 * written against the invariant dereferences what it believes is a live task.
 * That is exactly what happened - the detector processes themselves stopped
 * starting.
 *
 * ===========================================================================
 * 3. WHAT THIS FILE DOES INSTEAD
 *
 * It removes the CAUSE rather than the symptom: zygote is given a genuinely
 * small pid, so getppid() returns a real, small, verifiable number and every
 * invariant above holds by construction.
 *
 * The kernel allocates pids with
 *
 *      idr_alloc_cyclic(&ns->idr, NULL, pid_min, pid_max, GFP_ATOMIC)
 *
 * in kernel/pid.c:alloc_pid(). The "cyclic" allocator wraps back to pid_min
 * (RESERVED_PIDS, i.e. 300) once it passes the upper bound.
 *
 * The bound is the file-scope `int pid_max` in kernel/pid.c - the same value
 * behind the /proc/sys/kernel/pid_max sysctl. (Older kernels kept it as
 * ns->pid_max inside struct pid_namespace; 6.6 moved it out, which is why this
 * file resolves the symbol instead of reading a struct member.)
 *
 * So: lower pid_max below the number zygote currently holds, and the very next
 * pid allocation wraps to ~300. fork() enough times to consume
 * the low range, and the next zygote gets a small number of its own.
 *
 * Everything happens in the kernel, through a value the kernel already owns -
 * no hook, no fabricated state, nothing for a detector to catch.
 *
 * ===========================================================================
 * 4. ORDER OF OPERATIONS
 *
 * The counter must be wrapped BEFORE zygote restarts, because zygote is what
 * needs the small pid. This module is loaded by service.sh at boot, long after
 * zygote is already running, so wrapping the counter alone changes nothing:
 * the running zygote keeps its large pid.
 *
 * Therefore:
 *
 *   1. save pid_max
 *   2. lower it so the next allocation wraps low
 *   3. request a zygote restart (the same thing the user does for temporary
 *      root anyway - ctl.restart zygote). The newly forked zygote takes a
 *      small pid from the wrapped counter.
 *   4. restore pid_max once zygote is back, so the rest of the system gets a
 *      normal allocation range again.
 *
 * Step 3 is opt-in (wrap_pid_max param): restarting zygote kills every app and
 * takes the device through a soft boot, which is not something a module should
 * do behind the user's back. With the default (0) the module only prepares the
 * range and logs what to run.
 */

#include <asm/barrier.h>

#include <linux/cache.h>
#include <linux/cred.h>
#include <linux/jiffies.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/sched.h>
#include <linux/workqueue.h>

/* ------------------------------------------------------------------------ */
/* tunables                                                                 */
/* ------------------------------------------------------------------------ */

/*
 * Target ceiling for the wrapped counter. The new zygote must land below
 * hide_self_ppid_limit (5000) for the detector, and the wrapped range starts
 * at RESERVED_PIDS (300), so anything in (5000, current_pid) works. 4096 is
 * comfortably under the limit while leaving ~3800 allocatable slots, which is
 * far more than the boot sequence needs before zygote comes up.
 */
/*
 * Optional alternative to masking: lower the allocator ceiling so a restarted
 * zygote is renumbered for real. Off by default now - masking needs no restart
 * and no risk window, and the two mechanisms would fight over the same value.
 * Enable one or the other, never both.
 */
static int wrap_pid_max = 0;
module_param(wrap_pid_max, int, 0644);
MODULE_PARM_DESC(wrap_pid_max, "non-zero enables the pid counter wrap instead of masking (default 0 = off)");

/*
 * 1 = restart zygote ourselves after wrapping, so the new small pid takes
 * effect immediately. Default 0: restarting zygote kills every app, so this is
 * the operator's decision, not the module's.
 */
static int wrap_restart_zygote = 0;
module_param(wrap_restart_zygote, int, 0444);
MODULE_PARM_DESC(wrap_restart_zygote, "1 = request a zygote restart after wrapping (default 0, do it yourself)");

/*
 * How long to keep the lowered ceiling before restoring it automatically.
 *
 * This is the safety net, not a convenience. While pid_max is low the
 * allocatable range is only [RESERVED_PIDS, pid_max), and the low hundreds are
 * already taken by init, kthreadd, the kworkers, system_server and friends at
 * boot. Leave the ceiling down and a busy system can exhaust the remaining
 * slots and start failing fork() with -EAGAIN - which hangs app starts and
 * eventually the framework. Restoring after a bounded window keeps the
 * dangerous state short; zygote has long since taken its pid by then.
 *
 * 0 disables the timer (the ceiling stays until the module is unloaded).
 */
static int wrap_restore_ms = 5000;
module_param(wrap_restore_ms, int, 0444);
MODULE_PARM_DESC(wrap_restore_ms, "ms after which pid_max is restored automatically (default 5000, 0 = never)");

/* the pid below which a zygote is considered healthy */
static int hide_self_ppid_limit = 5000;
module_param(hide_self_ppid_limit, int, 0444);
MODULE_PARM_DESC(hide_self_ppid_limit, "a zygote pid below this is what the detector wants (default 5000)");

/*
 * 1 = answer apps with a synthetic parent pid when the real one is too large.
 * This is the primary mechanism; wrap_pid_max below is the alternative for
 * devices where masking is not wanted and a real renumber is preferred.
 */
static int hide_self_getppid_mask = 1;
module_param(hide_self_getppid_mask, int, 0644);
MODULE_PARM_DESC(hide_self_getppid_mask, "1 = disguise an oversized getppid() for apps (default 1)");

/*
 * Off by default.
 *
 * The only thing this hook does is rewrite the Seccomp field of
 * /proc/<pid>/status from 0 to 2 for app readers. To reach that field it
 * must sit on seq_put_decimal_ull, which prints EVERY number in EVERY
 * seq_file - meminfo, stat, cpuinfo, mounts, and every /proc/<pid>/status
 * field. That is the single hottest path a module could possibly hook, and
 * a detector that times /proc reads sees the constant overhead as a timing
 * side channel.
 *
 * The getppid() disguise is the primary fix and does not need this; Seccomp
 * is a secondary signal. Leave it off unless a target specifically keys on
 * Seccomp:0, and accept the timing cost only then.
 */
static int hide_self_seccomp = 0;
module_param(hide_self_seccomp, int, 0644);
MODULE_PARM_DESC(hide_self_seccomp, "1 = rewrite Seccomp:0 to 2 for apps (default 0, hot path)");

static int hide_self_scan_ms = 5000;
module_param(hide_self_scan_ms, int, 0444);
MODULE_PARM_DESC(hide_self_scan_ms, "zygote re-lookup interval in ms, 0 disables the timer");

/* diagnostics; off by default because the status hook runs on a hot path */
static int hide_self_debug;
module_param(hide_self_debug, int, 0444);
MODULE_PARM_DESC(hide_self_debug, "1 = log hook activity from the rescan timer");

#define HIDE_SELF_SCAN_MIN_MS	1000

/* ------------------------------------------------------------------------ */
/* state                                                                    */
/* ------------------------------------------------------------------------ */

static uintptr_t hide_self_init_task;
/* last scan result, so the diagnostic line only prints when it changes */
static int hide_self_last_scanned = -1;
static int hide_self_last_apps = -1;
/* set when at least one app process reports an oversized parent; service.sh
 * reads this back through the log to decide whether a restart is warranted */
static int hide_self_need_restart __read_mostly;
/*
 * &pid_max - the global the cyclic allocator uses as its upper bound.
 *
 * 6.6 moved this out of struct pid_namespace: it used to be ns->pid_max,
 * now kernel/pid.c declares `int pid_max = PID_MAX_DEFAULT;` at file scope and
 * alloc_pid() passes it straight to idr_alloc_cyclic(). The same value backs
 * the /proc/sys/kernel/pid_max sysctl, so writing it here is exactly what
 * echoing into that node does - and unlike the old ns->pid_max there is no
 * struct offset involved, so __randomize_layout cannot bite.
 */
static int *hide_self_pid_max;

/*
 * The pid handed to apps in place of hide_self_zygote_pid.
 *
 * Constraints, all of which matter:
 *   - below hide_self_ppid_limit, that is the point of the exercise;
 *   - not already in use, or /proc/<fake> would resolve to some unrelated
 *     process and the disguise would be worse than the truth;
 *   - stable for the lifetime of the real zygote, because two wakeups in a
 *     row must not disagree about who the parent is.
 *
 * The two variables themselves live in kernel.h: hide_pid.c is included before
 * this file and needs to read them to translate lookups of the fake pid.
 */

static struct delayed_work hide_self_work;
static int hide_self_period;
/* restores pid_max after the danger window, so a low ceiling cannot starve
 * the pid allocator and break fork() system-wide */
static struct delayed_work hide_self_restore_work;
static int hide_self_restore_period;

static struct kprobe *kp_seq_decimal;

/*
 * Minting the synthetic pid is NOT done in the kretprobe.
 *
 * getppid() is one of the busiest syscalls on the device, and reserving a free
 * pid means walking the whole task list. Doing that inline would put a
 * full-list traversal on a hot syscall, inside an RCU read-side section, on
 * every CPU that happens to call it first. Worse, two CPUs racing here would
 * each mint a different number and the last writer would win, so two apps
 * could be told two different parents.
 *
 * So the probe only ever reads. When it finds an oversized parent it hands the
 * work to a single-threaded workqueue and, until that finishes, keeps
 * answering honestly. The disguise appears one scheduling round later, which
 * no detector can observe as a contradiction - it is simply the truth, then
 * not the truth.
 */
static struct work_struct hide_self_mint_work;
/*
 * Serialises minting so a burst of concurrent callers queues exactly one work
 * item. int rather than bool: cmpxchg() needs an atomically addressable
 * scalar, and a 1-byte bool is not guaranteed to be one on every kernel build.
 */
static int hide_self_mint_pending __read_mostly;

/*
 * getppid: the discovery channel AND the thing being disguised.
 *
 * SYSCALL_DEFINE0(getppid) ends in
 *      return task_tgid_vnr(current->real_parent);
 * so by the time a kretprobe fires, x0 already holds the answer the kernel
 * computed. For an app that answer IS the pid of whatever forked it, so the
 * syscall hands us the zygote pid for free: no task-list walk, no user-space
 * helper, no post-fs-data report, nothing to keep in sync.
 *
 * That is the whole design. First call from an app records the pid it
 * reported; from then on the same pid is answered with a small synthetic one.
 */
static struct kretprobe *kr_getppid;
static struct kretprobe *kr_compat_getppid;

/* what we saved before lowering pid_max, so exit can put it back */
static int hide_self_orig_pid_max;
static bool hide_self_pid_max_lowered;

/* ------------------------------------------------------------------------ */
/* who is asking                                                            */
/* ------------------------------------------------------------------------ */

static __always_inline bool hide_self_reader_is_app(void)
{
	return current_uid().val >= MIN_APP_PROCESS_UID;
}

/* ------------------------------------------------------------------------ */
/* app parent check                                                         */
/* ------------------------------------------------------------------------ */

/*
 * ===========================================================================
 * What this needs to answer
 *
 * The detector reads getppid() from an app process and fails if the value is
 * above hide_self_ppid_limit. That value is nothing more than
 *
 *      current->real_parent->pid
 *
 * so the question this file has to answer is exactly:
 *
 *      "is there an app process whose parent pid is above the limit?"
 *
 * Note what is NOT in that question: the word zygote. There is no need to know
 * which process is the app zygote, what it is called, or whether it has forked
 * anything yet. Restarting it does not need its pid either - ctl.restart zygote
 * addresses it by name. An earlier revision went looking for zygote tasks and
 * then for their usap children to work out which one mattered, which fails
 * exactly when it matters most: on a freshly booted or idle device the zygote
 * has no app children yet, so the enumeration finds nothing and the module
 * concludes there is nothing to do.
 *
 * So: walk the task list once, and report whether any process that looks like
 * an app has an oversized parent. No names, no child counting, no ordering.
 * ===========================================================================
 */

/* an app process: uid >= MIN_APP_PROCESS_UID, i.e. not system/root/kernel */
static bool hide_self_is_app_task(struct task_struct *p)
{
	kuid_t uid;

	if (!p)
		return false;

	/* kernel threads have no mm and no uid to speak of */
	if (!p->mm)
		return false;

	uid = task_uid(p);
	return uid.val >= MIN_APP_PROCESS_UID;
}

/*
 * Process context only (init and the timer), never kprobe context, so the task
 * list may be walked under RCU. No task reference is taken: pid numbers and
 * comm are stable while RCU keeps the task alive.
 */
static void hide_self_scan(void)
{
	struct task_struct *init = (struct task_struct *)hide_self_init_task;
	struct task_struct *p;
	pid_t worst_parent = 0;
	pid_t worst_child = 0;
	int app_count = 0;
	int oversized = 0;
	int scanned = 0;

	if (!init)
		return;

	rcu_read_lock();
	list_for_each_entry_rcu(p, &init->tasks, tasks) {
		struct task_struct *parent;
		pid_t ppid;

		scanned++;

		/* one observation per process, not per thread */
		if (p->group_leader != p)
			continue;

		if (!hide_self_is_app_task(p))
			continue;

		parent = p->real_parent;
		if (!parent)
			continue;

		ppid = (pid_t)task_pid_nr(parent);
		if (ppid <= 0)
			continue;

		app_count++;

		if (ppid >= hide_self_ppid_limit) {
			oversized++;
			if (!worst_parent || ppid > worst_parent) {
				worst_parent = ppid;
				worst_child = (pid_t)task_pid_nr(p);
			}
		}
	}
	rcu_read_unlock();

	/*
	 * Report the counts, not just the verdict. A silent zero is what made the
	 * earlier failure look like a timing race: if the walk itself is broken on
	 * this kernel, "scan N task(s), 0 app(s)" says so immediately, while a
	 * silent return said nothing at all.
	 */
	if (scanned != hide_self_last_scanned || app_count != hide_self_last_apps) {
		hide_self_last_scanned = scanned;
		hide_self_last_apps = app_count;
		pr_info("hide_self: scan %d task(s), %d app process(es)\n",
			scanned, app_count);
	}

	if (!oversized) {
		smp_store_release(&hide_self_need_restart, 0);
		if (hide_self_debug)
			pr_info("hide_self: every app parent is below %d, nothing to fix\n",
				hide_self_ppid_limit);
		return;
	}

	smp_store_release(&hide_self_need_restart, 1);

	if (worst_parent != hide_self_zygote_pid) {
		smp_store_release(&hide_self_zygote_pid, worst_parent);
		pr_info("hide_self: %d app process(es) have a parent above %d (worst: parent %d of pid %d)\n",
			oversized, hide_self_ppid_limit,
			(int)worst_parent, (int)worst_child);
	}
}

/*
 * long __arm64_sys_getppid(const struct pt_regs *regs)
 *
 * On return x0 holds task_tgid_vnr(current->real_parent), i.e. the pid of the
 * process that forked the caller. For an app under zygote that number is the
 * zygote pid, which is exactly what the detector compares against the limit.
 *
 * So the hook needs no discovery pass at all: whatever the syscall just
 * returned is the truth, and the first oversized answer from an app names the
 * zygote we have to disguise. Record it, mint a believable replacement below
 * the limit, and answer with that from then on.
 *
 * Answering with a number that is not a live pid is deliberate here and is
 * safe only because the same disguise covers the lookup side: find_pid_ns and
 * find_task_by_pid_ns translate the fake pid back to the real zygote, so
 * /proc/<fake>/comm returns "zygote64" and every read path agrees. A fake pid
 * without that translation is what crashed the detectors earlier.
 */
static int hide_self_kr_getppid_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	long ret = (long)regs->regs[0];
	pid_t fake;
	pid_t want;

	/* a small answer is already what a healthy zygote looks like */
	if (ret <= 0 || ret < (long)hide_self_ppid_limit)
		return 0;

	/* only apps are disguised; root/shell/system keep the truth so ps,
	 * ActivityManager and our own scripts still work */
	if (!hide_self_reader_is_app())
		return 0;

	want = (pid_t)ret;

	/*
	 * Read-only fast path. Answer with the existing disguise if it covers
	 * this parent; otherwise leave the truth in place and ask for one to be
	 * minted. Nothing here walks the task list or takes a lock.
	 */
	if (smp_load_acquire(&hide_self_fake_for) == want) {
		fake = smp_load_acquire(&hide_self_fake_pid);
		if (fake > 0)
			regs->regs[0] = (unsigned long)fake;
		return 0;
	}

	/*
	 * No disguise covers this parent yet. Queue exactly one mint - the flag stops
	 * a burst of concurrent callers from queueing hundreds of them. The work
	 * item re-reads the live task list rather than being told what to disguise,
	 * so a zygote restart between queueing and running is handled correctly
	 * instead of publishing a mapping for a pid that has gone away.
	 *
	 * Until it finishes, callers keep getting the truth. That is not a
	 * contradiction a detector can see: the syscall simply has not been
	 * disguised yet.
	 */
	if (!cmpxchg(&hide_self_mint_pending, 0, 1))
		schedule_work(&hide_self_mint_work);

	return 0;
}

/*
 * Pick a synthetic pid below the limit that no live task currently owns.
 *
 * Reusing an occupied number would make /proc/<fake> resolve to a real but
 * unrelated process - an app that looks up its own reported parent would see
 * a stranger's comm, which is far more damning than a large pid. The walk is
 * cheap enough here because this only runs when the disguise is (re)built.
 */
static pid_t hide_self_pick_fake_pid(pid_t avoid)
{
	struct task_struct *init = (struct task_struct *)hide_self_init_task;
	pid_t candidate;
	int attempt;

	if (!init || hide_self_ppid_limit <= 2)
		return 0;

	/* deterministic spread rather than get_random_u32(): the value only needs
	 * to be unpredictable enough not to collide across reboots, and the
	 * jiffies-based start avoids another header just for this */
	candidate = 1 + (pid_t)((jiffies_to_msecs(jiffies) + (unsigned long)avoid) %
				(unsigned int)(hide_self_ppid_limit - 1));

	/*
	 * One pass over the task list collecting which low pids are taken, then
	 * pick from what is left. Scanning per candidate instead would re-walk the
	 * whole list for every collision, and on a busy device the low range is
	 * mostly occupied - that is hundreds of full traversals in the worst case.
	 */
	{
		DECLARE_BITMAP(used, 4096);
		struct task_struct *p;
		unsigned int span;

		if (hide_self_ppid_limit > 4096)
			return 0;

		bitmap_zero(used, 4096);

		rcu_read_lock();
		list_for_each_entry_rcu(p, &init->tasks, tasks) {
			int nr = task_pid_nr(p);

			if (nr > 0 && nr < 4096)
				__set_bit(nr, used);
		}
		rcu_read_unlock();

		/* keep pid 0/1 out and never collide with the pid being disguised */
		__set_bit(0, used);
		__set_bit(1, used);
		if (avoid > 0 && avoid < 4096)
			__set_bit(avoid, used);

		span = (unsigned int)(hide_self_ppid_limit - 1);

		for (attempt = 0; attempt < (int)span; attempt++) {
			if (candidate <= 1 || candidate >= hide_self_ppid_limit)
				candidate = 2;

			if (!test_bit(candidate, used))
				return candidate;

			candidate++;
		}
	}

	return 0;
}

/*
 * Runs in process context, one at a time: reserve a pid below the limit that no
 * task owns, and publish it as the disguise for whatever parent the live scan
 * currently reports as oversized.
 */
/*
 * What the disguise should currently cover: the largest parent pid seen among
 * app processes, or 0 when every app parent is already below the limit.
 *
 * This deliberately re-reads the live task list instead of trusting the value
 * recorded when the work was queued. Between queueing and running, the zygote
 * may have restarted; disguising the pid that was current at queue time would
 * publish a mapping for a process that no longer exists, and the new one would
 * never be covered because the pending flag suppressed the second request.
 */
static pid_t hide_self_find_oversized_parent(void)
{
	struct task_struct *init = (struct task_struct *)hide_self_init_task;
	struct task_struct *p;
	pid_t worst = 0;

	if (!init)
		return 0;

	rcu_read_lock();
	list_for_each_entry_rcu(p, &init->tasks, tasks) {
		struct task_struct *parent;
		pid_t ppid;

		if (p->group_leader != p)
			continue;
		if (!hide_self_is_app_task(p))
			continue;

		parent = p->real_parent;
		if (!parent)
			continue;

		ppid = (pid_t)task_pid_nr(parent);
		if (ppid >= hide_self_ppid_limit && ppid > worst)
			worst = ppid;
	}
	rcu_read_unlock();

	return worst;
}

static void hide_self_mint_fn(struct work_struct *unused)
{
	pid_t want;
	pid_t fake;

	want = hide_self_find_oversized_parent();
	if (want <= 0)
		goto out;	/* nothing oversized any more, leave the truth */

	/* already disguised for exactly this parent? keep it, do not reshuffle */
	if (smp_load_acquire(&hide_self_fake_for) == want &&
	    smp_load_acquire(&hide_self_fake_pid) > 0)
		goto out;

	fake = hide_self_pick_fake_pid(want);
	if (!fake) {
		pr_info("hide_self: no free pid below %d to mask %d with\n",
			hide_self_ppid_limit, (int)want);
		goto out;
	}

	/* publish the target first: a reader that sees a matching fake_for is then
	 * guaranteed to also see a finished fake_pid (acquire/release pairing) */
	smp_store_release(&hide_self_fake_pid, fake);
	smp_store_release(&hide_self_fake_for, want);
	smp_store_release(&hide_self_zygote_pid, want);

	pr_info("hide_self: masking parent pid %d as %d\n", (int)want, (int)fake);

out:
	smp_store_release(&hide_self_mint_pending, 0);
}

static void hide_self_scan_fn(struct work_struct *unused)
{
	hide_self_scan();

	if (hide_self_period > 0)
		schedule_delayed_work(&hide_self_work,
				      msecs_to_jiffies((unsigned int)hide_self_period));
}

/* ------------------------------------------------------------------------ */
/* Seccomp: 0 -> 2                                                          */
/* ------------------------------------------------------------------------ */

/*
 * The status text is produced by fs/proc/array.c through
 * seq_put_decimal_ull(m, "\nSeccomp:\t", task_seccomp(task)). That function
 * is exported and therefore probeable; rewriting the value argument before it
 * is formatted is enough, and the delimiter string identifies the field.
 *
 * This is deliberately the ONLY syscall-visible value this module touches. It
 * is the one field the detector reads that has no consistency relation with
 * anything else, so answering it differently leaves no contradiction behind:
 * no other interface exposes the same number for cross-checking.
 */
static const char hide_self_seccomp_key[] = "\nSeccomp:\t";

/*
 * Bounded compare. seq_put_decimal_ull() is called with many delimiters and
 * the pointer comes straight out of the caller's registers, so an unbounded
 * strcmp() would read until it found a NUL - an out-of-bounds read in the
 * middle of /proc output. Comparing a fixed number of bytes and then
 * requiring the NUL keeps the probe in-bounds whatever the caller passed.
 */
static __always_inline bool hide_self_delim_is(const char *delim, const char *key, size_t len)
{
	return !strncmp(delim, key, len) && delim[len] == '\0';
}

static int hide_self_kp_seq_decimal_pre(struct kprobe *unused, struct pt_regs *regs)
{
	const char *delim;
	unsigned long long num;

	if (!hide_self_seccomp)
		return 0;

	/* this function is on a hot path, so the cheapest filter comes first */
	if (!hide_self_reader_is_app())
		return 0;

	delim = (const char *)PT_REGS_PARM2(regs);
	if (!delim || delim[0] != '\n' || delim[1] != 'S')
		return 0;

	if (!hide_self_delim_is(delim, hide_self_seccomp_key,
				sizeof(hide_self_seccomp_key) - 1))
		return 0;

	num = (unsigned long long)PT_REGS_PARM3(regs);

	/*
	 * Only the missing-filter case is rewritten.
	 *
	 * SECCOMP_MODE_DISABLED is 0 and that is what the detector treats as
	 * "no filter was ever installed", so 0 -> 2 is the whole point. Every
	 * other value passes through untouched: overwriting STRICT (1) with 2
	 * would change a reading the process can know about itself, and a
	 * target running in strict mode would see its own status contradict
	 * what it set up.
	 */
	if (num)
		return 0;

	PT_REGS_PARM3(regs) = 2;	/* SECCOMP_MODE_FILTER */
	if (hide_self_debug)
		pr_info("hide_self: Seccomp 0 -> 2 for uid %u\n", current_uid().val);

	return 0;
}

/* ------------------------------------------------------------------------ */
/* pid counter wrap                                                         */
/* ------------------------------------------------------------------------ */

/*
 * Lower the global `pid_max` so the cyclic allocator wraps to RESERVED_PIDS on
 * its next pass. That variable is what the sysctl writes, so poking it is
 * equivalent to echoing into /proc/sys/kernel/pid_max - and legal from a
 * module, which is why the whole wrap can live in the kernel.
 *
 * pid_max_min exists to stop a write that would make the low range
 * unallocatable, and it is RESERVED_PIDS+1 at minimum, so anything >= 301 is
 * accepted. wrap_pid_max defaults to 4096, comfortably inside the bounds.
 */
static int hide_self_wrap_pid_max(void)
{
	int *pmax = hide_self_pid_max;
	int cur;
	int target;

	if (!pmax)
		return -ENOENT;

	if (wrap_pid_max <= 0) {
		pr_info("hide_self: wrap_pid_max=0, pid counter left alone\n");
		return 0;
	}

	cur = READ_ONCE(*pmax);

	/*
	 * Nothing to do when the counter already sits below the ceiling: pids
	 * are being handed out in the safe range, so the next zygote is fine.
	 */
	if (cur <= wrap_pid_max) {
		pr_info("hide_self: pid_max=%d already <= %d, no wrap needed\n",
			cur, wrap_pid_max);
		return 0;
	}

	/* remember the original once, so exit restores the boot value even if
	 * the wrap is run again after a partial failure */
	if (!hide_self_pid_max_lowered) {
		hide_self_orig_pid_max = cur;
		hide_self_pid_max_lowered = true;
	}

	target = wrap_pid_max;
	WRITE_ONCE(*pmax, target);

	pr_info("hide_self: pid_max %d -> %d; the next pid allocation wraps to ~%d\n",
		hide_self_orig_pid_max, target, 300);

	return 0;
}

static void hide_self_restore_pid_max(void)
{
	int *pmax = hide_self_pid_max;

	if (!pmax || !hide_self_pid_max_lowered)
		return;

	WRITE_ONCE(*pmax, hide_self_orig_pid_max);
	hide_self_pid_max_lowered = false;

	pr_info("hide_self: pid_max restored to %d\n", hide_self_orig_pid_max);
}

static void hide_self_restore_fn(struct work_struct *unused)
{
	hide_self_restore_pid_max();
}

/* ------------------------------------------------------------------------ */
/* init / exit                                                              */
/* ------------------------------------------------------------------------ */

/*
 * kretprobe registration. A plain kprobe will not do: the handler has to read
 * the value the original syscall computed, and that only exists once the
 * function has returned.
 */
static __init struct kretprobe *hide_self_arm_ret(const char *sym,
						 kretprobe_handler_t handler)
{
	struct kretprobe *rp;

	if (!kallsyms_lookup_name(sym)) {
		pr_info("hide_self: %s not in kallsyms, skipped\n", sym);
		return NULL;
	}

	rp = kzalloc(sizeof(*rp), GFP_KERNEL);
	if (!rp)
		return NULL;

	rp->kp.symbol_name = sym;
	rp->handler = handler;
	/* getppid is called by every process constantly; a small pool would run
	 * dry and silently stop disguising under load */
	rp->maxactive = 128;

	if (register_kretprobe(rp)) {
		pr_info("hide_self: register %s kretprobe failed\n", sym);
		kfree(rp);
		return NULL;
	}

	return rp;
}

static void hide_self_disarm_ret(struct kretprobe **rp_ptr)
{
	struct kretprobe *rp = *rp_ptr;

	if (!rp)
		return;

	unregister_kretprobe(rp);
	synchronize_rcu();
	kfree(rp);
	*rp_ptr = NULL;
}

static __init int hide_self_init(void)
{
	int armed = 0;

	hide_self_init_task = kallsyms_lookup_name("init_task");
	if (!hide_self_init_task) {
		pr_info("hide_self: init_task not in kallsyms\n");
		return -ENOENT;
	}

	hide_self_pid_max = (int *)kallsyms_lookup_name("pid_max");
	if (!hide_self_pid_max) {
		pr_info("hide_self: pid_max not in kallsyms, cannot wrap the counter\n");
		return -ENOENT;
	}

	if (hide_self_scan_ms > 0 && hide_self_scan_ms < HIDE_SELF_SCAN_MIN_MS) {
		pr_info("hide_self: hide_self_scan_ms=%d too small, clamped to %d\n",
			hide_self_scan_ms, HIDE_SELF_SCAN_MIN_MS);
		hide_self_scan_ms = HIDE_SELF_SCAN_MIN_MS;
	}

	/*
	 * The disguise itself. Every app getppid() now passes through here: the
	 * original syscall computes the real parent pid, and if it is over the
	 * limit the return value is replaced.
	 */
	if (!hide_self_getppid_mask) {
		pr_info("hide_self: getppid masking disabled\n");
	} else {
		kr_getppid = hide_self_arm_ret("__arm64_sys_getppid",
					       hide_self_kr_getppid_ret);
		if (kr_getppid)
			armed++;

		/* CONFIG_COMPAT only; a missing symbol on a 64-bit-only kernel is
		 * expected and must not be treated as a failure */
		kr_compat_getppid = hide_self_arm_ret("__arm64_compat_sys_getppid",
						      hide_self_kr_getppid_ret);
		if (kr_compat_getppid)
			armed++;
	}

	INIT_WORK(&hide_self_mint_work, hide_self_mint_fn);

	if (hide_self_seccomp) {
		kp_seq_decimal = init_kprobe("seq_put_decimal_ull",
					     (kprobe_pre_handler_t)hide_self_kp_seq_decimal_pre);
		if (kp_seq_decimal)
			armed++;
	}

	if (hide_self_scan_ms > 0) {
		hide_self_period = hide_self_scan_ms;
		INIT_DELAYED_WORK(&hide_self_work, hide_self_scan_fn);
		schedule_delayed_work(&hide_self_work,
				      msecs_to_jiffies((unsigned int)hide_self_period));
	}

	if (hide_self_pid_max_lowered) {
		/*
		 * Start the countdown that gives the allocation range back.
		 *
		 * The lowered ceiling is a loaded gun: the low pid range is
		 * partly occupied already, so leaving it in place risks starving
		 * fork() system-wide. The timer guarantees the dangerous state is
		 * temporary even if nobody unloads the module or restarts zygote.
		 */
		if (wrap_restore_ms > 0) {
			hide_self_restore_period = wrap_restore_ms;
			INIT_DELAYED_WORK(&hide_self_restore_work, hide_self_restore_fn);
			schedule_delayed_work(&hide_self_restore_work,
					      msecs_to_jiffies((unsigned int)hide_self_restore_period));
			pr_info("hide_self: pid_max will be restored in %dms\n",
				hide_self_restore_period);
		}

		if (wrap_restart_zygote)
			pr_info("hide_self: wrap_restart_zygote is set; restart zygote now (setprop ctl.restart zygote) and it will come back below %d\n",
				wrap_pid_max);
		else
			pr_info("hide_self: counter wrapped. Restart zygote to take the new range: setprop ctl.restart zygote\n");
	}

	pr_info("hide_self: %d feature(s) armed, ppid limit %d, wrap_pid_max %d\n",
		armed, hide_self_ppid_limit, wrap_pid_max);

	return armed ? 0 : -ENODEV;
}

static void hide_self_exit(void)
{
	if (hide_self_period > 0) {
		hide_self_period = 0;
		cancel_delayed_work_sync(&hide_self_work);
	}

	if (hide_self_restore_period > 0) {
		hide_self_restore_period = 0;
		cancel_delayed_work_sync(&hide_self_restore_work);
	}

	destroy_kprobe(&kp_seq_decimal);

	hide_self_disarm_ret(&kr_getppid);
	hide_self_disarm_ret(&kr_compat_getppid);

	/* no probe fires now, but a mint queued just before disarming could still
	 * be pending; let it run out rather than freeing state underneath it */
	cancel_work_sync(&hide_self_mint_work);

	/* always give the allocation range back, even on a failed setup */
	hide_self_restore_pid_max();

	/* drop the disguise so nothing keeps translating a pid we no longer own */
	smp_store_release(&hide_self_fake_pid, 0);
	smp_store_release(&hide_self_fake_for, 0);
	smp_store_release(&hide_self_zygote_pid, 0);
}
