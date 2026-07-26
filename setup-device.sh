#!/usr/bin/env bash
#
# setup-device.sh — provision a rooted Android device (emulator or physical phone
# with Magisk) for sockstack: push frida-server and, if missing, a static tcpdump.
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

# Frida's release artefacts are not named after the Android ABI string: a device
# reporting arm64-v8a needs frida-server-…-android-arm64. Translate, so the
# download hint below points at a file that exists.
case "$ABI" in
    arm64-v8a)            FRIDA_ARCH=arm64 ;;
    armeabi-v7a|armeabi)  FRIDA_ARCH=arm ;;
    x86_64)               FRIDA_ARCH=x86_64 ;;
    x86)                  FRIDA_ARCH=x86 ;;
    *)                    FRIDA_ARCH='<arch>' ;;
esac

if [ -n "$FRIDA_BIN" ]; then
    echo "[+] pushing frida-server: $FRIDA_BIN"
    echo "    (this must be a frida-server 17.x built for ${ABI:-the device ABI})"
    adb -s "$SERIAL" push "$FRIDA_BIN" "$FRIDA_DST"
    SU "chmod 755 '$FRIDA_DST'"

    # A frida-server for the wrong architecture pushes and chmods exactly like a
    # correct one: the file is there and executable, so provisioning "succeeds"
    # and the failure surfaces much later, inside a run, as a twenty-second wait
    # and "could not bring frida-server up". Start it here instead, where the
    # binary being pushed is still in front of us and the cause can be named.
    echo "[+] verifying frida-server actually runs on this device"
    SU "pkill -f '$FRIDA_DST'" >/dev/null 2>&1 || true
    sleep 1
    SU "nohup '$FRIDA_DST' --daemonize >/dev/null 2>&1 &" >/dev/null 2>&1 || true
    RUNNING=""
    for _ in 1 2 3 4 5 6 7 8; do
        sleep 1
        if [ -n "$(adb -s "$SERIAL" shell "pidof $(basename "$FRIDA_DST")" | tr -d '\r')" ]; then
            RUNNING=yes
            break
        fi
    done
    if [ -n "$RUNNING" ]; then
        echo "[+] frida-server is up and stays up"
    else
        echo "[!] frida-server was pushed but will not stay running." >&2
        echo "    Most likely the binary does not match this device: it reports" >&2
        echo "    ABI '${ABI:-unknown}', and you pushed $(basename "$FRIDA_BIN")." >&2
        echo "    Download frida-server-17.x.y-android-${FRIDA_ARCH}.xz, unpack it," >&2
        echo "    and run this script again. Check by hand with:" >&2
        echo "      adb -s $SERIAL shell '$FRIDA_DST --version'" >&2
        exit 1
    fi
elif SU "test -x '$FRIDA_DST'"; then
    echo "[i] no frida-server binary given — one is already on the device"
    echo "    (sockstack starts it on demand; pass a binary as arg 2 to replace it)"
else
    echo "[!] no frida-server on the device and none given as arg 2." >&2
    echo "    sockstack cannot hook anything without it. Download a matching" >&2
    echo "    frida-server 17.x for ABI '${ABI:-unknown}' and re-run:" >&2
    echo "      ./setup-device.sh $SERIAL ./frida-server-17.x.y-android-${FRIDA_ARCH}" >&2
    exit 1
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
