#!/system/bin/sh
PATH=/data/adb/ksu/bin:$PATH
MODDIR=${0%/*}
KO="$MODDIR/ko/fgetpriority.ko"

# ---- tunables (edit here, or export before sourcing) ----------------------
# comma separated comm names to hide
HIDE_COMM=${HIDE_COMM:-ksud}
# rescan interval in ms, used to pick up a new pid after a soft reboot
# ksud 是开机后固定存在的守护进程，pid 不会每秒变化。1 秒一次的
# 全表扫描（每次还 kzalloc 快照）是打开应用变慢的主因之一，降到 30 秒。
HIDE_SCAN_MS=${HIDE_SCAN_MS:-30000}
# 1 = only hide from app-uid callers (ps from adb keeps working)
HIDE_APP_ONLY=${HIDE_APP_ONLY:-1}
# optional decoy name for /proc/modules, empty = leave the real name
HIDE_MODULE_NAME=${HIDE_MODULE_NAME:-}

# ---- refuse to hide anything the system cannot live without ---------------
# The kernel module also refuses these, but failing here keeps a bad config
# from being loaded at all: hiding zygote/system_server/init makes every app
# unlaunchable (their pids stop resolving, so process management breaks) and
# the only way back is a recovery boot. Cheap check, expensive mistake.
for _bad in init zygote zygote64 zygote32 usap32 usap64 system_server surfaceflinger; do
	case ",$HIDE_COMM," in
	*",$_bad,"*)
		echo "fgetpriority: refusing to load, hide_comm_list contains '$_bad'" >&2
		echo "fgetpriority: hiding a system-critical process breaks process management" >&2
		exit 0
		;;
	esac
done

# ---- pid counter wrap settings -------------------------------------------
# Target ceiling for the wrap. Must stay below 5000 (the detector's limit)
# and above the low hundreds already occupied at boot.
WRAP_PID_MAX=${WRAP_PID_MAX:-4096}
# How long the lowered ceiling is kept before the module restores it.
WRAP_RESTORE_MS=${WRAP_RESTORE_MS:-5000}

PARAMS="hide_comm_list=$HIDE_COMM hide_scan_ms=$HIDE_SCAN_MS hide_only_from_app=$HIDE_APP_ONLY"
PARAMS="$PARAMS wrap_pid_max=$WRAP_PID_MAX wrap_restore_ms=$WRAP_RESTORE_MS"
[ -n "$HIDE_MODULE_NAME" ] && PARAMS="$PARAMS hide_module_name=$HIDE_MODULE_NAME"

# ---- kallsyms_lookup_name address (kptr_restrict round trip) --------------
kptr_set=$(cat /proc/sys/kernel/kptr_restrict)
echo 1 > /proc/sys/kernel/kptr_restrict
addr=$(grep " kallsyms_lookup_name$" /proc/kallsyms | awk {'print "0x"$1'})
echo "$kptr_set" > /proc/sys/kernel/kptr_restrict

# ---- reload ---------------------------------------------------------------
# the module may have been renamed, so match on the recorded decoy too
for name in fgetpriority "$HIDE_MODULE_NAME"; do
	[ -z "$name" ] && continue
	if grep -q "^$name " /proc/modules; then
		rmmod "$name" 2>/dev/null
	fi
done

if ! insmod "$KO" kallsyms_lookup_name_fn="$addr" $PARAMS 2>/dev/null; then
	ksud insmod "$KO" kallsyms_lookup_name_fn="$addr" $PARAMS
fi

# ---- zygote restart so the new pid range takes effect ---------------------
# Lowering pid_max only changes where the NEXT allocation lands. The zygote
# that is already running keeps its large pid, and every app inherits that
# number through getppid(). Restarting it is what makes it re-fork into the
# wrapped range, which is the whole point.
#
# The module does the identification, not this script.
#
# Walking /proc from the shell was wrong for two reasons. It takes the first
# zygote* it meets, and /proc is ordered by pid, so on a device that has grown
# a stale "zygote" plus two "zygote64" the first hit is often not the process
# apps hang off - the real one was 13406 while the script decided 1827 and
# concluded nothing needed doing. And a shell cannot tell which zygote is the
# app parent at all; the kernel can, by counting usap children.
#
# So: confirm the disguise armed by reading the module's own log.
#
# The getppid() kretprobe discovers the oversized parent on its own and queues
# a mint; no scan, no restart, no zygote pid needed. The only thing worth
# echoing back here is whether a disguise has actually been published yet.
_mask=$(dmesg | sed -n 's/.*hide_self: masking parent pid [0-9]\+ as \([0-9]\+\).*/\1/p' | tail -n1)

if [ -n "$_mask" ]; then
	echo "fgetpriority: getppid disguise armed, fake parent pid $_mask" >&2
else
	echo "fgetpriority: no disguise yet - it appears on the first oversized getppid() from an app" >&2
fi

# ---- verify ---------------------------------------------------------------
# hide_self prints the wrap result and hide_pid the armed hook count.
dmesg | grep -E "hide_self: .*(wrap|pid_max|zygote)|hide_pid: .*(armed|rescan)" | tail -n 8
