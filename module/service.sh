#!/system/bin/sh
PATH=/data/adb/ksu/bin:$PATH
MODDIR=${0%/*}
KO="$MODDIR/ko/fgetpriority.ko"

# ---- tunables (edit here, or export before sourcing) ----------------------
# comma separated comm names to hide
HIDE_COMM=${HIDE_COMM:-ksud}
# rescan interval in ms, used to pick up a new pid after a soft reboot
HIDE_SCAN_MS=${HIDE_SCAN_MS:-1000}
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

PARAMS="hide_comm_list=$HIDE_COMM hide_scan_ms=$HIDE_SCAN_MS hide_only_from_app=$HIDE_APP_ONLY"
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

# ---- verify ---------------------------------------------------------------
# hide_pid prints the armed count and the pid it settled on. Seeing pid 0 here
# is normal: ksud may not be running yet at boot, the rescan picks it up later.
dmesg | grep -E "hide_pid: .*(armed|rescan|target)" | tail -n 5
