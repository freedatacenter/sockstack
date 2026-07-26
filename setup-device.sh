#!/usr/bin/env bash
#
# setup-device.sh — provision a rooted Android device (emulator or physical phone
# with Magisk) for droidtrace: push frida-server and, if missing, a static tcpdump.
#
# Usage:
#   ./setup-device.sh <device-id> [frida-server-binary] [tcpdump-binary]
#
# Download a matching frida-server 17.x for your device architecture from
#   https://github.com/frida/frida/releases  (frida-server-17.x.y-android-<arch>.xz)
# The major version must match the host's Frida, which friTap 2.x pins to 17.
# The script prints the device ABI before pushing — a mismatch there is the most
# common reason frida-server "starts" and then does nothing.
#
# A static tcpdump for Android is only needed on stock phones — emulator images
# already ship one in /system/bin.
set -euo pipefail

SERIAL="${1:?usage: ./setup-device.sh <device-id> [frida-server] [tcpdump]}"
FRIDA_BIN="${2:-}"
TCPDUMP_BIN="${3:-}"
FRIDA_DST=/data/local/tmp/frida-server
TCPDUMP_DST=/data/local/tmp/tcpdump

# Detect how to gain root on this device.
#
# The su branch must pass the whole command as ONE argument. `su -c foo || bar`
# is tokenised by the device shell before su ever runs, so the operator applies
# to `su` itself and the right-hand side executes as the unprivileged shell user
# — including redirections, which then fail on root-only paths while appearing
# to run "under su". Quoting the payload keeps the entire compound inside su.
if [ "$(adb -s "$SERIAL" shell id -u | tr -d '\r')" = "0" ]; then
    SU() { adb -s "$SERIAL" shell "$1"; }
    echo "[+] root shell available directly"
elif [ "$(adb -s "$SERIAL" shell su -c id -u | tr -d '\r')" = "0" ]; then
    SU() {
        local payload=${1//\'/\'\\\'\'}
        adb -s "$SERIAL" shell "su -c '$payload'"
    }
    echo "[+] root via su -c (Magisk)"
else
    echo "[!] no root on $SERIAL — emulator: 'adb -s $SERIAL root'; phone: install Magisk" >&2
    exit 1
fi

ABI="$(adb -s "$SERIAL" shell getprop ro.product.cpu.abi | tr -d '\r')"
echo "[+] device ABI: ${ABI:-unknown}"

if [ -n "$FRIDA_BIN" ]; then
    echo "[+] pushing frida-server: $FRIDA_BIN"
    echo "    (this must be a frida-server 17.x built for ${ABI:-the device ABI})"
    adb -s "$SERIAL" push "$FRIDA_BIN" "$FRIDA_DST"
    SU "chmod 755 '$FRIDA_DST'"
else
    echo "[i] no frida-server binary given — skipping (pass it as arg 2)"
fi

# On some Android 14 arm64 images perfetto's heap profiling raises SIGSEGV and
# takes the target process down at launch. Clearing this property stopped it on
# the images where we hit it; it is a persist property, so it only takes effect
# after a reboot. If a target still dies instantly on launch, check the related
# heapprofd/traced_perf properties too — the exact trigger varies by image.
echo "[+] disabling perfetto tracing (Android 14 launch-crash workaround)"
SU "setprop persist.traced.enable 0" || true

# Check every location the runner will later look in, so a second run does not
# re-push a binary that is already there.
if SU "test -x '$TCPDUMP_DST' || test -x /system/bin/tcpdump || command -v tcpdump >/dev/null"; then
    echo "[+] tcpdump already present on device"
elif [ -n "$TCPDUMP_BIN" ]; then
    echo "[+] pushing tcpdump: $TCPDUMP_BIN"
    adb -s "$SERIAL" push "$TCPDUMP_BIN" "$TCPDUMP_DST"
    SU "chmod 755 '$TCPDUMP_DST'"
else
    echo "[i] no tcpdump on device and none provided — pcap capture will be skipped"
    echo "    (pass a static tcpdump binary as arg 3, or use --tcpdump later)"
fi

echo "[+] done."
echo "    The perfetto property is a persist prop: reboot before the first run —"
echo "      adb -s $SERIAL reboot"
