// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 \xx
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#pragma once

#define MIN_APP_PROCESS_UID      10000
#define MIN_ISOLATED_PROCESS_UID 90000

static const int AID_USER_OFFSET = 100000;

/* (uid_t)-1 is unmappable; unlike an isolated UID, it cannot own tasks. */
#define HIDDEN_PRIORITY_UID (-1)

#ifdef TIF_SECCOMP
#define is_seccomp_enabled() test_thread_flag(TIF_SECCOMP)
#else
#define is_seccomp_enabled() (!!current->seccomp.mode)
#endif

#ifdef MODULE
static uintptr_t init_ns_ksym_p __read_mostly = 0x0;
static __always_inline struct user_namespace *init_ns_p(void)
{
	return (struct user_namespace *)init_ns_ksym_p;
}
static int resolve_init_user_ns(void)
{ 
	init_ns_ksym_p = (uintptr_t)kallsyms_lookup_name("init_user_ns");
	if (!init_ns_ksym_p)
		return -ENOENT;
	return 0;
}
#else
#define init_ns_p() ({ &init_user_ns; })
static int resolve_init_user_ns(void) { return 0; }
#endif

static __always_inline bool getpriority_should_swap(int who)
{
	if (unlikely(!is_seccomp_enabled()))
		return false;

	int cuid = current_uid().val;

	/* only an app calling about another app matters. System uids are all
	 * below 10000 (init=0, system=1000, ...), so the two bounds here are the
	 * whole rule: caller is an app AND target is an app, and they are not the
	 * same uid. No isolated/user-offset normalisation is needed - a cross-app
	 * lookup is caught by the raw uid comparison alone. */
	if (unlikely(cuid < MIN_APP_PROCESS_UID || who < MIN_APP_PROCESS_UID))
		return false;

	return cuid != who;
}

