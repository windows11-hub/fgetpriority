### fgetpriority

A small LKM that filters two independent things:

1. `sys_getpriority` / `sys_setpriority` / `sys_ioprio_get` / `sys_ioprio_set`
   (hides a uid from app-to-app queries), see `routine_raw.c`
2. every pid -> task resolution path, plus `/proc/<pid>`, for processes whose
   comm matches a configured list (default `ksud`), see `hide_pid.c`

Usage (LKM):

```shell
insmod fgetpriority.ko
```

Usage (LKM, if above fails):

```shell
#!/bin/sh

kptr_set=$(cat /proc/sys/kernel/kptr_restrict)
echo 1 > /proc/sys/kernel/kptr_restrict
addr=$(grep " kallsyms_lookup_name$" /proc/kallsyms | awk {'print "0x"$1'})
echo $kptr_set > /proc/sys/kernel/kptr_restrict

insmod fgetpriority.ko kallsyms_lookup_name_fn="$addr"
```

Usage (built-in):
- just compile it in :^)

## Parameters

| name | default | meaning |
| --- | --- | --- |
| `kallsyms_lookup_name_fn` | 0 | address to use when /proc/kallsyms is unreadable |
| `hide_comm_list` | `ksud` | comma separated `struct task_struct.comm` names to hide |
| `hide_scan_ms` | `1000` | rescan interval for re-locating the pid, `0` disables rescanning |
| `hide_only_from_app` | `1` | `1` = hide only from app-uid callers, `0` = hide from every caller |
| `hide_module_name` | empty | if set, the name `/proc/modules` reports instead of the real one |
| `hide_zygote_abnormal` | `1` | `1` = also hide a zygote whose pid is above `hide_zygote_pid_limit` (temporary root), `0` = leave it |
| `hide_zygote_pid_limit` | `5000` | pid threshold above which a zygote is treated as soft-restarted |

```shell
insmod fgetpriority.ko hide_comm_list="ksud,ksud_watch" hide_scan_ms=500
```

`hide_scan_ms` values below 250 are clamped: each scan walks every task on the
device, so a very small interval costs real CPU.

`ksud` is not one process. The daemon stays resident, and each `ksud ...`
command line is a second process with the same comm that lives for a few
milliseconds. A single-pid tracker latches onto one of those, publishes it, and
then loses the daemon when the client exits - which leaves the daemon visible
until the next scan. The whole set is published as one immutable snapshot
behind an RCU pointer, sized to exactly the number of matches - there is no
fixed cap, so a soft restart that leaves zygote plus several same-comm
children behind all get hidden. Readers in kprobe context take
rcu_read_lock() and dereference the pointer; a writer allocates a fresh
snapshot and frees the old one through call_rcu().

## What hide_pid.c covers

Hooking `find_pid_ns()` and `find_task_by_pid_ns()` instead of individual
syscalls, because every pid-taking syscall converges on those two. The result,
for a caller that matches `hide_only_from_app`, is `ESRCH` / `ENOENT`:

- `kill`, `tkill`, `tgkill`, `rt_sigqueueinfo`, `rt_tgsigqueueinfo`
- `pidfd_open`, `pidfd_getfd`
- `sched_{get,set}{affinity,param,scheduler,attr}`
- `getpriority`, `setpriority`, `ioprio_{get,set}` with a pid
- `getpgid`, `getsid`, `prlimit64`, `get_robust_list`, `set_robust_list`
- `ptrace`, `kcmp`, `waitid`
- `migrate_pages`, `move_pages`, `process_vm_readv`, `process_vm_writev`
- `getrusage` with an explicit who
- `stat("/proc/<pid>")` and `open("/proc/<pid>/...")`

Three kprobes are used, not one per syscall: `find_pid_ns`,
`find_task_by_pid_ns` and `find_ge_pid`. The third one is what makes the picture
consistent - it is the iterator behind `readdir("/proc")`, so the numeric entry
never appears at all instead of appearing and then refusing to open (that
inconsistency would be a far louder anomaly than a process that is simply not
there).

## Soft reboot

A zygote / system_server restart gives the target a new pid while the hooks
stay armed. A delayed work item rescans `init_task.tasks` every
`hide_scan_ms` milliseconds and republishes the whole set, so the pid is back
within one interval and the exposed window is bounded. If nothing matches any
more the set is emptied instead of hiding an unrelated process that inherits a
recycled number.

```shell
dmesg | grep 'hide_pid:'
# hide_pid: 3 hook(s) armed, 2 pid(s) hidden
# hide_pid:   pid 1417
# hide_pid:   pid 1488
# hide_pid: hiding pid 2051        <- after a respawn
```

If `hide_comm_list` names the wrong comm, the module stays armed and silently
hides nothing; check that first when the detector still sees the process
(`cat /proc/<pid>/comm`).

## Compatibility

- CONFIG_ARM64=y
- CONFIG_KALLSYMS=y
- CONFIG_KALLSYMS_ALL=y (if used as LKM)
- CONFIG_KPROBES=y (for the pid filter; the priority filter degrades to branch
  patching, the pid filter simply reports 0 hooks armed)
