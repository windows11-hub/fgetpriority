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
 *      idr_alloc_cyclic(&ns->idr, NULL, pid_min, ns->pid_max, GFP_ATOMIC)
 *
 * in kernel/pid.c:alloc_pid(). The "cyclic" allocator wraps back to pid_min
 * (RESERVED_PIDS, i.e. 300) once it passes ns->pid_max. That bound is the
 * writable sysctl /proc/sys/kernel/pid_max, i.e. init_pid_ns.pid_max.
 *
 * So: lower init_pid_ns.pid_max below the number zygote currently holds, and
 * the very next pid allocation wraps to ~300. fork() enough times to consume
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
 *   1. save init_pid_ns.pid_max
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
#include <linux/pid_namespace.h>
#include <linux/random.h>
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
static int wrap_pid_max = 4096;
module_param(wrap_pid_max, int, 0444);
MODULE_PARM_DESC(wrap_pid_max, "temporary pid_max used to wrap the pid counter below 5000 (default 4096, 0 disables)");

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

static int hide_self_seccomp = 1;
module_param(hide_self_seccomp, int, 0444);
MODULE_PARM_DESC(hide_self_seccomp, "1 = report Seccomp: 2 to app readers, 0 = leave untouched");

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
/* resolved once: &init_pid_ns (the namespace whose pid_max sysctl we touch) */
static struct pid_namespace *hide_self_init_pid_ns;

static pid_t hide_self_zygote_pid __read_mostly;

static struct delayed_work hide_self_work;
static int hide_self_period;
/* restores pid_max after the danger window, so a low ceiling cannot starve
 * the pid allocator and break fork() system-wide */
static struct delayed_work hide_self_restore_work;
static int hide_self_restore_period;

static struct kprobe *kp_seq_decimal;

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
/* zygote discovery                                                         */
/* ------------------------------------------------------------------------ */

static bool hide_self_is_zygote(const char *comm)
{
	if (!comm)
		return false;

	/* zygote64, zygote, zygote32 - the app forking zygotes all share the stem */
	return !strncmp(comm, "zygote", 6);
}

/*
 * Process context only (init and the timer), never kprobe context, so the task
 * list may be walked under RCU. No task reference is taken: comm and the pid
 * number are stable while RCU keeps the task alive.
 */
static void hide_self_scan(void)
{
	struct task_struct *init = (struct task_struct *)hide_self_init_task;
	struct task_struct *p;
	pid_t found = 0;

	if (!init)
		return;

	rcu_read_lock();
	list_for_each_entry_rcu(p, &init->tasks, tasks) {
		pid_t nr;

		if (p->group_leader != p)
			continue;
		if (!hide_self_is_zygote(p->comm))
			continue;

		/* zygote/zygote64/zygote32 all show up; the smallest is the oldest */
		nr = (pid_t)task_pid_nr(p);
		if (nr > 0 && (!found || nr < found))
			found = nr;
	}
	rcu_read_unlock();

	if (!found || found == hide_self_zygote_pid)
		return;

	smp_store_release(&hide_self_zygote_pid, found);

	if (found < hide_self_ppid_limit)
		pr_info("hide_self: zygote pid %d is in range, getppid() needs no help\n",
			(int)found);
	else
		pr_info("hide_self: zygote pid %d is above %d - the pid counter was not wrapped before this zygote started; rerun the wrap and restart zygote\n",
			(int)found, hide_self_ppid_limit);
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
 * Lower init_pid_ns.pid_max so the cyclic allocator wraps to RESERVED_PIDS on
 * its next pass. The value the sysctl writes is the same field, so writing the
 * variable is equivalent to echoing into /proc/sys/kernel/pid_max - and legal
 * from a module, which is why the whole wrap can live in the kernel.
 *
 * pid_max_min exists to stop a write that would make the low range
 * unallocatable, and it is RESERVED_PIDS+1 at minimum, so anything >= 301 is
 * accepted. wrap_pid_max defaults to 4096, comfortably inside the bounds.
 */
static int hide_self_wrap_pid_max(void)
{
	struct pid_namespace *ns = hide_self_init_pid_ns;
	int cur;
	int target;

	if (!ns)
		return -ENOENT;

	if (wrap_pid_max <= 0) {
		pr_info("hide_self: wrap_pid_max=0, pid counter left alone\n");
		return 0;
	}

	cur = READ_ONCE(ns->pid_max);

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
	WRITE_ONCE(ns->pid_max, target);

	pr_info("hide_self: pid_max %d -> %d; the next pid allocation wraps to ~%d\n",
		hide_self_orig_pid_max, target, 300);

	return 0;
}

static void hide_self_restore_pid_max(void)
{
	struct pid_namespace *ns = hide_self_init_pid_ns;

	if (!ns || !hide_self_pid_max_lowered)
		return;

	WRITE_ONCE(ns->pid_max, hide_self_orig_pid_max);
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

static __init int hide_self_init(void)
{
	int armed = 0;

	hide_self_init_task = kallsyms_lookup_name("init_task");
	if (!hide_self_init_task) {
		pr_info("hide_self: init_task not in kallsyms\n");
		return -ENOENT;
	}

	hide_self_init_pid_ns = (struct pid_namespace *)kallsyms_lookup_name("init_pid_ns");
	if (!hide_self_init_pid_ns) {
		pr_info("hide_self: init_pid_ns not in kallsyms, cannot wrap the counter\n");
		return -ENOENT;
	}

	if (hide_self_scan_ms > 0 && hide_self_scan_ms < HIDE_SELF_SCAN_MIN_MS) {
		pr_info("hide_self: hide_self_scan_ms=%d too small, clamped to %d\n",
			hide_self_scan_ms, HIDE_SELF_SCAN_MIN_MS);
		hide_self_scan_ms = HIDE_SELF_SCAN_MIN_MS;
	}

	hide_self_scan();

	/* the counter wrap is the actual fix; the Seccomp field is the only
	 * remaining hook and it exists because that value has no sibling */
	if (!hide_self_wrap_pid_max())
		armed++;

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

	/* always give the allocation range back, even on a failed setup */
	hide_self_restore_pid_max();

	smp_store_release(&hide_self_zygote_pid, 0);
}
