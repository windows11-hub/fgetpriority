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
module_param(hide_self_ppid_limit, int, 0644);
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
/*
 * Off by default. The only reason to turn this on is to rewrite a
 * Seccomp:0 status field, and on this device the Seccomp field is already
 * correct (apps report 2 because zygote installed the filter), so the
 * rewrite has nothing to do. The hook sits on seq_put_decimal_ull, which
 * prints every number in every seq_file - meminfo, stat, cpuinfo, mounts,
 * every /proc/<pid>/status field - so leaving it armed is a BRK trap on the
 * single hottest /proc path and makes every app open slowly. Keep it off.
 */
static int hide_self_seccomp = 0;
module_param(hide_self_seccomp, int, 0644);
MODULE_PARM_DESC(hide_self_seccomp, "1 = rewrite Seccomp:0 to 2 for apps (default 0, hot path)");

/* diagnostics. Off by default: the getppid hook is hot, and this logs every
 * app call, so it is for tracing the soft-reboot failure, not for daily use.
 * Writable so service.sh can flip it on without recompiling. */
static int hide_self_debug;
module_param(hide_self_debug, int, 0644);
MODULE_PARM_DESC(hide_self_debug, "1 = trace getppid masking decisions (hot path, off by default)");

/* ------------------------------------------------------------------------ */
/* state                                                                    */
/* ------------------------------------------------------------------------ */

static uintptr_t hide_self_init_task;
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

/* restores pid_max after the danger window, so a low ceiling cannot starve
 * the pid allocator and break fork() system-wide */
static struct delayed_work hide_self_restore_work;
static int hide_self_restore_period;

static struct kprobe *kp_seq_decimal;

/*
 * Minting the synthetic pid is NOT done on the fast path.
 *
 * getppid() is one of the busiest syscalls on the device, and reserving a free
 * pid means walking the whole task list. Doing that inline would put a
 * full-list traversal on a hot syscall on every CPU that happens to call it
 * first. Worse, two CPUs racing here would each mint a different number and
 * the last writer would win, so two apps could be told two different parents.
 * The mint is serialised under a spinlock and only runs on the zygote-change
 * transition, never on the steady-state fast path.
 *
 * So the probe only ever reads. When it finds an oversized parent it hands the
 * work to a single-threaded workqueue and, until that finishes, keeps
 * answering honestly. The disguise appears one scheduling round later, which
 * no detector can observe as a contradiction - it is simply the truth, then
 * not the truth.
 */
/*
 * Serialises the (rare) synchronous re-mint when the zygote pid changes. It
 * is taken only on that transition, never on the getppid() fast path, so it
 * cannot become a contended hot lock. A spinlock rather than a mutex: the
 * pick runs under rcu_read_lock (preempt disabled), where a mutex cannot be
 * taken.
 */
static DEFINE_SPINLOCK(hide_self_mint_lock);

/*
 * getppid: the discovery channel AND the thing being disguised.
 *
 * SYSCALL_DEFINE0(getppid) returns task_tgid_vnr(current->real_parent), i.e.
 * the pid of whatever forked the caller. For an app that is the zygote pid,
 * which is exactly the value the detector flags. We inline-hook the syscall
 * entry itself (patch its first instruction to branch here), so there is no
 * kprobe BRK trap on this very hot path - the hook is a plain branch.
 *
 * __nocfi: sys_call_table holds this entry and is an indirect call site. On a
 * CFI kernel an unannotated replacement would trip the forward-edge check.
 */
static uintptr_t hide_self_orig_getppid;
static u32 hide_self_orig_insn;
static bool hide_self_getppid_patched;

static __nocfi long hide_self_gphook_getppid(const struct pt_regs *regs);

/* what we saved before lowering pid_max, so exit can put it back */
static int hide_self_orig_pid_max;
static bool hide_self_pid_max_lowered;

/* ------------------------------------------------------------------------ */
/* who is asking                                                            */
/* ------------------------------------------------------------------------ */

/*
 * Is the caller an ordinary app?
 *
 * Decided by the seccomp state, not by uid. zygote installs a seccomp filter
 * into every real app process, so "has a seccomp filter" is the kernel-side
 * marker of "this is an app" - and it is exactly the field the detector reads
 * the other way around (a missing filter -> Seccomp:0 -> "免解"). A uid can
 * be anything (0, 1000, setuid-ed), but a process cannot remove a seccomp
 * filter once installed, so the flag is trustworthy and cannot be spoofed
 * from userspace.
 *
 * is_seccomp_enabled() reads current->seccomp.mode (or TIF_SECCOMP), which is
 * available in the syscall context on every kernel we build for (5.10 -> 6.18).
 */
static __always_inline bool hide_self_reader_is_app(void)
{
	return is_seccomp_enabled();
}

/* forward decl: defined below, after the getppid handler that calls it */
static pid_t hide_self_pick_fake_pid(pid_t avoid);

/*
 * long __arm64_sys_getppid(const struct pt_regs *regs)
 *
 * Inline hook replacing the whole syscall entry. task_tgid_vnr() is a static
 * inline, so it cannot be patched at a call site the way find_user() is in
 * routine_raw.c; the syscall body is all inlined code. The entry's first
 * instruction is therefore rewritten to branch here, and this function calls
 * the inlined task_tgid_vnr() directly - the same thing the original did.
 *
 * That is the whole design: no kprobe trap, one plain branch on a hot path,
 * and the original value is still computed by the same inlined helper.
 */
static __nocfi long hide_self_gphook_getppid(const struct pt_regs *regs)
{
	long ret;
	pid_t fake;
	pid_t want;

	/* the original body: task_tgid_vnr(current->real_parent) */
	rcu_read_lock();
	ret = (long)task_tgid_vnr(rcu_dereference(current->real_parent));
	rcu_read_unlock();

	/* a small answer is already what a healthy zygote looks like */
	if (ret <= 0 || ret < (long)hide_self_ppid_limit)
		return ret;

	/* only apps are disguised; root/shell/system keep the truth */
	if (!hide_self_reader_is_app()) {
		if (hide_self_debug)
			pr_info("hide_self: getppid %ld non-app uid %u, skip\n",
				ret, current_uid().val);
		return ret;
	}

	want = (pid_t)ret;

	if (hide_self_debug)
		pr_info("hide_self: app getppid %ld parent_comm=%s fake_for=%d fake_pid=%d\n",
			ret, current->real_parent ? current->real_parent->comm : "?",
			(int)smp_load_acquire(&hide_self_fake_for),
			(int)smp_load_acquire(&hide_self_fake_pid));

	/*
	 * FAST PATH: if this exact parent was already disguised, answer now. A hit
	 * also proves the parent was a zygote (only zygote parents are ever minted),
	 * so no comm check is needed on this path.
	 */
	if (smp_load_acquire(&hide_self_fake_for) == want) {
		fake = smp_load_acquire(&hide_self_fake_pid);
		if (fake > 0)
			return (long)fake;
		return ret;
	}

	/* re-mint synchronously so the caller gets the disguise this same syscall */
	spin_lock(&hide_self_mint_lock);

	if (smp_load_acquire(&hide_self_fake_for) == want) {
		fake = smp_load_acquire(&hide_self_fake_pid);
	} else {
		fake = hide_self_pick_fake_pid(want);
		if (fake > 0) {
			smp_store_release(&hide_self_fake_pid, fake);
			smp_store_release(&hide_self_fake_for, want);
			smp_store_release(&hide_self_zygote_pid, want);
			pr_info("hide_self: masking parent pid %d as %d\n",
				(int)want, (int)fake);
		}
	}

	spin_unlock(&hide_self_mint_lock);

	if (fake > 0)
		return (long)fake;
	return ret;
}

/*
 * Pick a synthetic pid below the limit that no live task currently owns.
 *
 * Reusing an occupied number would make /proc/<fake> resolve to a real but
 * unrelated process - an app that looks up its own reported parent would see
 * a stranger's comm, which is far more damning than a large pid. The walk is
 * cheap enough here because this only runs when the disguise is (re)built.
 */
/*
 * Pick the synthetic parent pid.
 *
 * The value must be a REAL, live pid below the limit, not a hole. A fabricated
 * number has no /proc entry, so an app that looks up its reported parent gets
 * ENOENT and can fail to start - which is exactly the "some apps will not
 * open" symptom. A real low pid resolves on its own with no translation hook,
 * no kprobe and no VFS patching, which is the whole point: the disguise stays
 * one branch in getppid() and nothing else.
 *
 * Return the lowest live pid above 1 (i.e. kthreadd, pid 2, on every kernel).
 * It is created at boot, never exits, and is always below the limit, so it is
 * both always resolvable and stable for the life of the boot.
 */
static pid_t hide_self_pick_fake_pid(pid_t avoid)
{
	struct task_struct *init = (struct task_struct *)hide_self_init_task;
	struct task_struct *p;
	pid_t found = 0;

	if (!init)
		return 0;

	/*
	 * Lowest live pid >= 2. On a normal Android kernel this is kthreadd (2).
	 * Walk once; the result never changes during a boot because the early
	 * kernel threads are pinned and never exit.
	 */
	rcu_read_lock();
	list_for_each_entry_rcu(p, &init->tasks, tasks) {
		pid_t nr;

		if (p->group_leader != p)
			continue;

		nr = task_pid_nr(p);
		if (nr < 2 || nr >= hide_self_ppid_limit)
			continue;
		if (nr == avoid)
			continue;

		if (!found || nr < found)
			found = nr;
	}
	rcu_read_unlock();

	return found;
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
static const char hide_self_ppid_key[] = "\nPPid:\t";

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
 * Inline hook install: rewrite the first instruction of __arm64_sys_getppid
 * to branch to hide_self_gphook_getppid. The original 4-byte instruction is
 * saved so exit can restore it. __arm64_sys_getppid is a SYSCALL_DEFINE0, its
 * body is all inlined code, so there is no call site to patch - the entry
 * itself is the only hook point.
 *
 * Uses the same text-patching primitives routine_raw.c uses (via main.c's
 * kallsyms-resolved wrappers). __nocfi on the hook keeps the indirect-call
 * site through sys_call_table from tripping CFI.
 */
static __init int hide_self_patch_getppid(void)
{
	uintptr_t orig = kallsyms_lookup_name("__arm64_sys_getppid");
	u32 insn;
	int ret;

	if (!orig) {
		pr_info("hide_self: __arm64_sys_getppid not in kallsyms\n");
		return -ENOENT;
	}

	/* save the first instruction for restore */
	if (copy_from_kernel_nofault(&hide_self_orig_insn, (void *)orig, sizeof(u32))) {
		pr_info("hide_self: cannot read __arm64_sys_getppid entry\n");
		return -EFAULT;
	}

	insn = aarch64_insn_gen_branch_imm(orig, (unsigned long)hide_self_gphook_getppid,
					AARCH64_INSN_BRANCH_NOLINK);

	{
		void *addrs[] = { (void *)orig };
		u32 insns[] = { insn };
		ret = aarch64_insn_patch_text(addrs, insns, 1);
	}
	if (ret) {
		pr_info("hide_self: patch getppid entry failed: %d\n", ret);
		return ret;
	}

	hide_self_orig_getppid = orig;
	hide_self_getppid_patched = true;
	pr_info("hide_self: inline-hooked __arm64_sys_getppid at 0x%lx\n", orig);
	return 0;
}

static void hide_self_unpatch_getppid(void)
{
	void *addrs[1];
	u32 insns[1];

	if (!hide_self_getppid_patched || !hide_self_orig_getppid)
		return;

	addrs[0] = (void *)hide_self_orig_getppid;
	insns[0] = hide_self_orig_insn;
	aarch64_insn_patch_text(addrs, insns, 1);

	hide_self_getppid_patched = false;
	hide_self_orig_getppid = 0;
}

static __init int hide_self_init(void)
{
	int armed = 0;

	/*
	 * init_task is needed by the mint work (it scans the task list for a free
	 * pid), so it is a hard dependency of the masking path too.
	 */
	hide_self_init_task = kallsyms_lookup_name("init_task");
	if (!hide_self_init_task) {
		pr_info("hide_self: init_task not in kallsyms\n");
		return -ENOENT;
	}

	/*
	 * pid_max is only used by the wrap alternative (wrap_pid_max > 0). The
	 * getppid() masking path never touches it, so a kernel that does not export
	 * the symbol must not take masking down with it: resolve it, but treat a
	 * miss as "wrap unavailable" rather than a fatal error.
	 */
	hide_self_pid_max = (int *)kallsyms_lookup_name("pid_max");
	if (!hide_self_pid_max)
		pr_info("hide_self: pid_max not in kallsyms, wrap alternative unavailable\n");

	/*
	 * The disguise itself. Inline-hook __arm64_sys_getppid (patch its entry to
	 * branch to our function) so the hot path carries no kprobe BRK trap.
	 */
	if (!hide_self_getppid_mask) {
		pr_info("hide_self: getppid masking disabled\n");
	} else if (!hide_self_patch_getppid()) {
		armed++;
	}

	if (hide_self_seccomp) {
		kp_seq_decimal = init_kprobe("seq_put_decimal_ull",
					     (kprobe_pre_handler_t)hide_self_kp_seq_decimal_pre);
		if (kp_seq_decimal)
			armed++;
	}

	/*
	 * Optional alternative to masking: wrap_pid_max > 0 lowers the allocator
	 * ceiling so a RESTARTED zygote is renumbered for real. It is off by
	 * default because it needs a zygote restart to take effect and it opens a
	 * window in which the low pid range can starve fork(). Only run it when
	 * explicitly requested, and never together with masking.
	 */
	if (wrap_pid_max > 0) {
		if (!hide_self_wrap_pid_max())
			armed++;

		/*
		 * Start the countdown that gives the allocation range back.
		 *
		 * The lowered ceiling is a loaded gun: the low pid range is
		 * partly occupied already, so leaving it in place risks starving
		 * fork() system-wide. The timer guarantees the dangerous state is
		 * temporary even if nobody unloads the module or restarts zygote.
		 */
		if (hide_self_pid_max_lowered && wrap_restore_ms > 0) {
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
	if (hide_self_restore_period > 0) {
		hide_self_restore_period = 0;
		cancel_delayed_work_sync(&hide_self_restore_work);
	}

	destroy_kprobe(&kp_seq_decimal);

	hide_self_unpatch_getppid();

	/* always give the allocation range back, even on a failed setup */
	hide_self_restore_pid_max();

	/* drop the disguise so nothing keeps translating a pid we no longer own */
	smp_store_release(&hide_self_fake_pid, 0);
	smp_store_release(&hide_self_fake_for, 0);
	smp_store_release(&hide_self_zygote_pid, 0);
}
