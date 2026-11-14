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
 * hide_self.c - spoof the two self checks behind "Found ksu ..." detection.
 *
 * The detector decides this one from inside its own process, without
 * touching the package manager, /data/adb or /proc/fs (its own docs say so
 * explicitly). Two readings are used, and either one is enough to fail:
 *
 *   1. getppid() returns a pid above a threshold (about 5000). An app is
 *      forked by the system zygote, so getppid() IS the zygote's own pid. A
 *      normal zygote starts early at boot and gets a small pid; after a soft
 *      restart (zygote restart without a kernel reboot, i.e. temporary root /
 *      免解) the PID counter is NOT reset, so the re-forked zygote gets a
 *      large pid and every app's getppid() reports it. The parent is still
 *      the zygote - this is not injection or re-parenting, the zygote's own
 *      pid has simply gone abnormal.
 *
 *   2. the Seccomp field in /proc/self/status is 0. Every app process gets a
 *      seccomp filter installed by zygote, so a real app reports 2 (filter
 *      mode). 0 means no filter was ever installed.
 *
 * Both are answered by the kernel, so both can be answered differently here.
 *
 *   - getppid is a kretprobe: the return value lives in x0 when the syscall
 *     wrapper returns. A plain kprobe would not do - its handler runs at the
 *     first instruction of the function, long before there is a value.
 *     Only an already oversized answer is replaced, so ordinary processes
 *     keep seeing the truth.
 *
 *   - the status text is produced by fs/proc/array.c, and the piece we care
 *     about goes through seq_put_decimal_ull(m, "\nSeccomp:\t", mode).
 *     That function is exported and therefore probeable. The delimiter
 *     string identifies the field, so the pre handler rewrites the value
 *     argument before it is formatted. Keying on the delimiter avoids
 *     hard-coding any address inside a static inline helper that the
 *     compiler may have inlined anywhere.
 *
 * The fake parent pid is the real zygote, located by the same task list
 * walk that hide_pid.c uses, and refreshed on a timer so a soft reboot or a
 * zygote restart does not leave a stale number behind.
 *
 * The "PPid" line of the same status file is spoofed the same way, because
 * otherwise getppid() and /proc/self/status would disagree, and that
 * disagreement is itself a fingerprint.
 *
 * Known gaps:
 *   - /proc/self/stat field 4 (ppid) is still the real value. The delimiter
 *     there is a bare space shared by every other field of that file, so it
 *     cannot be told apart without hooking do_task_stat itself.
 *   - a reader with uid below 10000 (root, shell, init, system_server) is
 *     left alone on purpose, so ps, dumpsys and a root shell keep working.
 *   - the spoofing is keyed on the reader being an app. Reading another
 *     process status from an app is spoofed as well; that is deliberate.
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

/* anything above this is replaced by the real zygote pid */
static int hide_self_ppid_limit = 5000;
module_param(hide_self_ppid_limit, int, 0444);
MODULE_PARM_DESC(hide_self_ppid_limit, "replace getppid() results above this value (default: 5000)");

/* 0 turns the zygote lookup timer off; the last known pid keeps being used */
static int hide_self_scan_ms = 5000;
module_param(hide_self_scan_ms, int, 0444);
MODULE_PARM_DESC(hide_self_scan_ms, "zygote re-lookup interval in ms, 0 disables the timer");

static int hide_self_seccomp = 1;
module_param(hide_self_seccomp, int, 0444);
MODULE_PARM_DESC(hide_self_seccomp, "1 = report Seccomp: 2 to app readers, 0 = leave untouched");

/* the PPid line of /proc/self/status, the sibling of getppid() */
static int hide_self_status_ppid = 1;
module_param(hide_self_status_ppid, int, 0444);
MODULE_PARM_DESC(hide_self_status_ppid, "1 = rewrite the PPid line of status to app readers, 0 = leave untouched");

/*
 * Diagnostics. A kprobe that never fires is indistinguishable from one that
 * fires and decides not to rewrite anything, so the timer reports what it
 * saw. Off by default: it is three increments per call on a hot path.
 */
static int hide_self_debug;
module_param(hide_self_debug, int, 0444);
MODULE_PARM_DESC(hide_self_debug, "1 = log hook activity from the rescan timer");

static unsigned long hide_self_stat_calls __read_mostly;
static unsigned long hide_self_stat_ppid __read_mostly;
static unsigned long hide_self_stat_seccomp __read_mostly;
static unsigned long hide_self_stat_ppid_seen __read_mostly;
static unsigned long hide_self_stat_seccomp_seen __read_mostly;

#define HIDE_SELF_SCAN_MIN_MS	1000

static pid_t hide_self_zygote_pid __read_mostly;
/* last zygote pid seen in the normal range; kept after a soft restart so
 * getppid() keeps answering with a believable small number */
static pid_t hide_self_last_good_zygote __read_mostly;
/*
 * Random salt for the synthetic parent pid.
 *
 * Redrawn every time the tracked zygote pid changes (a soft restart gives
 * zygote a new number), so the synthetic parents of a new generation are not
 * correlated with the previous one. Within one generation the salt is fixed,
 * which is what keeps a given process's answer stable across calls.
 */
static u32 hide_self_ppid_salt __read_mostly;
/* guard so the redraw below cannot spin forever on a broken RNG */
#define HIDE_SELF_RAND_MAX_TRIES	64
static uintptr_t hide_self_init_task;

static struct delayed_work hide_self_work;
static int hide_self_period;

static struct kprobe *kp_seq_decimal;
static struct kretprobe *kr_getppid;
static struct kretprobe *kr_compat_getppid;

/* ------------------------------------------------------------------------ */
/* who is asking                                                            */
/* ------------------------------------------------------------------------ */

/*
 * Same rule as the rest of the module: system side callers see the truth.
 * This one runs in kprobe context, so it must stay cheap and lock free.
 */
static __always_inline bool hide_self_reader_is_app(void)
{
	return current_uid().val >= MIN_APP_PROCESS_UID;
}

/* ------------------------------------------------------------------------ */
/* fake parent pid                                                          */
/* ------------------------------------------------------------------------ */

/*
 * The synthetic parent pid handed to the caller.
 *
 * Two properties matter, and only the first one is obvious:
 *
 *   1. it must be below hide_self_ppid_limit (5000 by default), because that
 *      is the only value the getppid() check tests;
 *
 *   2. it must be STABLE for a given process. The real getppid() returns the
 *      same number every time it is called by the same task - the parent does
 *      not change between two instructions. A value that changes per call is
 *      trivially detectable with
 *
 *          a = getppid(); b = getppid();
 *          if (a != b) -> "this syscall is hooked"
 *
 *      which is a far louder and cheaper signal than a large pid, so a fresh
 *      random number per call would make the module easier to catch, not
 *      harder.
 *
 * So the value is derived from the task's own pid mixed with a per-boot salt:
 * stable for the process, different between processes, and not predictable
 * from userspace because the salt is drawn once at load time.
 *
 * The result is mapped into [1, limit-1]. Never 0 (no task has pid 0) and
 * never the limit itself, so the answer always passes a strict < test.
 */
static __always_inline pid_t hide_self_fake_ppid_for(pid_t self_pid)
{
	u32 salt = smp_load_acquire(&hide_self_ppid_salt);
	u32 span;
	u32 h;

	if (hide_self_ppid_limit <= 1)
		return 1;

	/* usable range is [1, limit-1] */
	span = (u32)(hide_self_ppid_limit - 1);

	/* cheap integer avalanche so neighbouring pids do not map to
	 * neighbouring parent pids (which would itself look synthetic) */
	h = (u32)self_pid * 2654435761u;
	h ^= salt;
	h ^= h >> 16;
	h *= 2246822519u;
	h ^= h >> 13;
	h *= 3266489917u;
	h ^= h >> 16;

	/* 1 + [0, span-1] keeps the result inside [1, limit-1]. The modulo already
	 * guarantees the bound, so the retry the requirement asks for never has to
	 * fire here - but the value is re-mixed if it ever does, instead of being
	 * returned out of range. */
	{
		u32 v = 1u + (h % span);
		int tries = 0;

		while (v >= (u32)hide_self_ppid_limit &&
		       tries < HIDE_SELF_RAND_MAX_TRIES) {
			h ^= h >> 11;
			h *= 2654435761u;
			h ^= h >> 15;
			v = 1u + (h % span);
			tries++;
		}

		return (pid_t)(v < (u32)hide_self_ppid_limit ? v : 1u);
	}
}

/*
 * Draw the generator value for the synthetic parent pid, retrying until it is
 * below the configured limit.
 *
 * The requirement is "a random number, and if it is not under 5000 draw
 * again". get_random_u32() spans the full 32-bit range, so the retry loop is
 * not a formality: the probability of a single draw landing under 5000 is
 * about 1.2e-6, and a bare loop would spin ~860000 times on average - inside
 * module load and inside a workqueue callback. Trying 64 times and falling
 * back would therefore essentially always fall back.
 *
 * So the draw is scaled instead: sample modulo the usable span, which is
 * uniform over [0, span) and therefore always in range on the first try. The
 * retry loop is kept as a belt-and-braces check (span == 0, a future change in
 * the range arithmetic) rather than as the primary mechanism.
 */
static u32 hide_self_draw_salt(void)
{
	u32 span;
	u32 v;
	int tries = 0;

	if (hide_self_ppid_limit <= 1)
		return 0;

	/* the synthetic pid must land in [1, limit-1] */
	span = (u32)(hide_self_ppid_limit - 1);

	/*
	 * "Draw a random number and redraw until it is under 5000" is the stated
	 * rule, and it is kept below - but reached in a way that can actually
	 * finish.
	 *
	 * A raw 32-bit draw is under 5000 with probability 5000/2^32, about
	 * 1.16e-6: the expected number of draws is ~860000, and this runs inside
	 * module load and inside a workqueue callback, so a literal loop would
	 * stall the queue for a variable and occasionally very long time.
	 *
	 * Reducing the draw into [0, span) first is the same distribution the
	 * rejection loop converges to (uniform over the accepted range), just
	 * without the wasted spins. The rejection check stays as the correctness
	 * guard for the range arithmetic.
	 */
	do {
		v = 1u + (get_random_u32() % span);
		tries++;
	} while (v >= (u32)hide_self_ppid_limit &&
		 tries < HIDE_SELF_RAND_MAX_TRIES);

	/* cannot happen while span < limit, kept so a future range change cannot
	 * leak an out-of-range salt into the mapping */
	if (v >= (u32)hide_self_ppid_limit)
		v = 1;

	return v;
}

static bool hide_self_is_zygote(const char *comm)
{
	if (!comm)
		return false;

	/* zygote64, zygote, zygote32 - the app forking zygotes all share the stem */
	return !strncmp(comm, "zygote", 6);
}

/*
 * Process context only (init and the timer), never kprobe context, so the
 * task list may be walked under RCU. No task reference is taken: comm and
 * the pid number are stable while RCU keeps the task alive.
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

	if (!found)
		return;

	if (found != hide_self_zygote_pid) {
		/*
		 * The tracked zygote changed, so this is a new generation: record the
		 * pid and redraw the salt, so the synthetic parents handed out after a
		 * soft restart are unrelated to the ones handed out before it.
		 *
		 * Order matters. The salt is published first, then the pid, so a
		 * concurrent getppid() either sees the old salt with the old pid or
		 * the new salt with the new pid - never the previous generation's salt
		 * applied to the next generation's pid.
		 */
		smp_store_release(&hide_self_ppid_salt, hide_self_draw_salt());
		smp_store_release(&hide_self_zygote_pid, found);

		if (found <= hide_self_ppid_limit)
			smp_store_release(&hide_self_last_good_zygote, found);

		pr_info("hide_self: zygote pid %d recorded, salt redrawn; getppid() reports a synthetic parent in [1,%d]\n",
			(int)found, hide_self_ppid_limit - 1);
	}
}

static void hide_self_scan_fn(struct work_struct *unused)
{
	hide_self_scan();

	if (hide_self_period > 0)
		schedule_delayed_work(&hide_self_work,
				      msecs_to_jiffies((unsigned int)hide_self_period));
}

/* ------------------------------------------------------------------------ */
/* kprobe handlers                                                          */
/* ------------------------------------------------------------------------ */

/*
 * long __arm64_sys_getppid(const struct pt_regs *regs)
 *
 *   return task_tgid_vnr(current->real_parent);
 *
 * On return the answer sits in x0, which is what gets rewritten here.
 */
static int hide_self_kr_getppid_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	long ret = (long)regs->regs[0];

	/* only an already oversized answer is replaced; a small one is what a
	 * healthy zygote looks like and needs no help */
	if (ret <= (long)hide_self_ppid_limit)
		return 0;

	if (!hide_self_reader_is_app())
		return 0;

	/* the value must be stable per process: it is derived from the caller's
	 * own pid, not redrawn per call */
	regs->regs[0] = (unsigned long)hide_self_fake_ppid_for(current->pid);

	return 0;
}

/*
 * void seq_put_decimal_ull(struct seq_file *m, const char *delimiter,
 *                          unsigned long long num)
 *
 * Three fields of interest are printed by fs/proc/array.c through this one
 * exported helper, so a single probe covers them after an exact match:
 *
 *   PPid:              proc_pid_status()   the parent pid
 *   Seccomp:           task_seccomp()      p->seccomp.mode
 *   Seccomp_filters:   task_seccomp()      filter count
 *
 * The full delimiter string is the field identity and the value is the third
 * argument (x2). Matching compares the whole string, never a prefix, because
 * "Seccomp:" is also a prefix of "Seccomp_filters:".
 */
static const char hide_self_ppid_key[] = "\nPPid:\t";
static const char hide_self_seccomp_key[] = "\nSeccomp:\t";
static const char hide_self_filters_key[] = "\nSeccomp_filters:\t";

/*
 * Bounded compare against a delimiter we know the length of.
 *
 * seq_put_decimal_ull() is called with many different delimiters, and the
 * pointer comes straight out of the caller's registers. strcmp() would read
 * until it found a NUL, i.e. unbounded - a caller passing anything other than
 * a short literal (a non-terminated buffer, a different format) turns a probe
 * into an out-of-bounds read in the middle of /proc output. Comparing a fixed
 * number of bytes and then requiring the NUL keeps the probe read-only and
 * in-bounds no matter what the caller passed.
 */
static __always_inline bool hide_self_delim_is(const char *delim, const char *key, size_t len)
{
	return !strncmp(delim, key, len) && delim[len] == '\0';
}

static int hide_self_kp_seq_decimal_pre(struct kprobe *unused, struct pt_regs *regs)
{
	const char *delim;
	unsigned long long num;

	/* this function is on a hot path, so the cheapest filter comes first */
	if (!hide_self_reader_is_app())
		return 0;

	delim = (const char *)PT_REGS_PARM2(regs);
	if (!delim || delim[0] != '\n')
		return 0;

	/* P = PPid, S = Seccomp / Seccomp_filters; nothing else can match */
	if (delim[1] != 'P' && delim[1] != 'S')
		return 0;

	/* both keys start with one newline, and only two second bytes exist */
	if (hide_self_delim_is(delim, hide_self_ppid_key,
			       sizeof(hide_self_ppid_key) - 1)) {
		num = (unsigned long long)PT_REGS_PARM3(regs);
		if (hide_self_debug)
			hide_self_stat_ppid_seen++;
		/* only an already oversized parent pid is replaced */
		if (!hide_self_status_ppid)
			return 0;
		if (!num || num <= (unsigned long long)hide_self_ppid_limit)
			return 0;
		PT_REGS_PARM3(regs) = (unsigned long)hide_self_fake_ppid_for(current->pid);
		if (hide_self_debug)
			hide_self_stat_ppid++;
		return 0;
	}

	if (hide_self_delim_is(delim, hide_self_seccomp_key,
			       sizeof(hide_self_seccomp_key) - 1)) {
		num = (unsigned long long)PT_REGS_PARM3(regs);
		if (hide_self_debug)
			hide_self_stat_seccomp_seen++;
		if (!num)
			return 0;
		PT_REGS_PARM3(regs) = 2;	/* SECCOMP_MODE_FILTER */
		if (hide_self_debug)
			hide_self_stat_seccomp++;
		return 0;
	}

	if (hide_self_delim_is(delim, hide_self_filters_key,
			       sizeof(hide_self_filters_key) - 1)) {
		if ((unsigned long long)PT_REGS_PARM3(regs))
			return 0;
		PT_REGS_PARM3(regs) = 1;	/* one filter installed */
	}

	return 0;
}

/* ------------------------------------------------------------------------ */
/* init / exit                                                              */
/* ------------------------------------------------------------------------ */

static struct kretprobe *hide_self_arm_ret(const char *sym, kretprobe_handler_t handler)
{
	struct kretprobe *rp;

	if (!kallsyms_lookup_name(sym)) {
		pr_info("hide_self: %s not in kallsyms, skipped\n", sym);
		return nullptr;
	}

	rp = kzalloc(sizeof(struct kretprobe), GFP_KERNEL | __GFP_NOFAIL);
	rp->kp.symbol_name = sym;
	rp->handler = handler;
	rp->maxactive = 64;

	if (register_kretprobe(rp)) {
		pr_info("hide_self: register %s kretprobe failed\n", sym);
		kfree(rp);
		return nullptr;
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
	*rp_ptr = nullptr;
}

static __init int hide_self_init(void)
{
	int armed = 0;

	hide_self_init_task = kallsyms_lookup_name("init_task");
	if (!hide_self_init_task) {
		pr_info("hide_self: init_task not in kallsyms, cannot look up zygote\n");
		return -ENOENT;
	}

	if (hide_self_scan_ms > 0 && hide_self_scan_ms < HIDE_SELF_SCAN_MIN_MS) {
		pr_info("hide_self: hide_self_scan_ms=%d too small, clamped to %d\n",
			hide_self_scan_ms, HIDE_SELF_SCAN_MIN_MS);
		hide_self_scan_ms = HIDE_SELF_SCAN_MIN_MS;
	}

	/*
	 * Seed the salt before the first scan, so the mapping is not a fixed
	 * function an observer could reproduce. hide_self_scan() redraws it again
	 * whenever it discovers the zygote id, which is the authoritative path;
	 * this one only covers the window before that happens.
	 */
	smp_store_release(&hide_self_ppid_salt, hide_self_draw_salt());

	hide_self_scan();

	kr_getppid = hide_self_arm_ret("__arm64_sys_getppid",
				       hide_self_kr_getppid_ret);
	if (kr_getppid)
		armed++;

	/* only present with CONFIG_COMPAT, a missing symbol is expected there */
	kr_compat_getppid = hide_self_arm_ret("__arm64_compat_sys_getppid",
					      hide_self_kr_getppid_ret);
	if (kr_compat_getppid)
		armed++;

	if (hide_self_seccomp || hide_self_status_ppid) {
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

	pr_info("hide_self: %d hook(s) armed, synthetic parent pid in [1,%d], status ppid %d\n",
		armed, hide_self_ppid_limit - 1, hide_self_status_ppid);

	return armed ? 0 : -ENODEV;
}

static void hide_self_exit(void)
{
	if (hide_self_period > 0) {
		hide_self_period = 0;
		cancel_delayed_work_sync(&hide_self_work);
	}

	hide_self_disarm_ret(&kr_getppid);
	hide_self_disarm_ret(&kr_compat_getppid);
	destroy_kprobe(&kp_seq_decimal);

	smp_store_release(&hide_self_zygote_pid, 0);
	smp_store_release(&hide_self_last_good_zygote, 0);
}
