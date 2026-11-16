#!/system/bin/sh
PATH=/data/adb/ksu/bin:$PATH
MODDIR=${0%/*}
KO="$MODDIR/ko/fgetpriority.ko"

# This script only LOADS the module. Every tunable lives on the module
# parameters themselves (hide_self.c / hide_pid.c); passing values here
# duplicates the module's defaults and, when the two drift apart, the script
# silently re-enables a code path the module default has turned off - which
# is exactly what broke the soft-reboot behaviour.

# ---- kallsyms_lookup_name address (kptr_restrict round trip) --------------
kptr_set=$(cat /proc/sys/kernel/kptr_restrict)
echo 1 > /proc/sys/kernel/kptr_restrict
addr=$(grep " kallsyms_lookup_name$" /proc/kallsyms | awk {'print "0x"$1'})
echo "$kptr_set" > /proc/sys/kernel/kptr_restrict

# ---- load (never unload) -------------------------------------------------
# The module unlinks itself from /proc/modules and deletes /sys/module/<name>,
# so lsmod cannot detect it. It instead exposes a dedicated flag at
# /sys/kernel/fgetpriority/loaded (value 1). Read that: if it says 1 the
# module (and its .text branch patches) is already resident and must NOT be
# reloaded - a reload would re-apply a patch that is already in place, fail,
# and fall back to the kprobe (BRK-trap) path that makes apps open slowly.
# Only insmod when the flag is absent.
if [ "$(cat /sys/kernel/fgetpriority/loaded 2>/dev/null)" = "1" ]; then
	: # already loaded - leave it and its patches untouched
elif ! insmod "$KO" kallsyms_lookup_name_fn="$addr"; then
	ksud insmod "$KO" kallsyms_lookup_name_fn="$addr"
fi
