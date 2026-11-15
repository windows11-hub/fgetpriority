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

# ---- reload ---------------------------------------------------------------
if lsmod | grep -q fgetpriority; then
	rmmod "$KO"
fi

if ! insmod "$KO" kallsyms_lookup_name_fn="$addr"; then
	ksud insmod "$KO" kallsyms_lookup_name_fn="$addr"
fi
