#!/usr/bin/env bash
#
# preflight.sh — is this machine and this device ready to run sockstack right now?
#
# Written for the ten minutes before a demo, where the useful question is not
# "is it installed" but "will a run work". So the last check is a real run: a
# short capture against a real package, whose result decides the verdict. Every
# other check exists to tell you *which* link is broken when it does not.
#
# Usage:
#   ./scripts/preflight.sh --device emulator-5554 --package com.example.app
#   ./scripts/preflight.sh --device emulator-5554 --no-canary   # checks only
#
# Exit status is 0 only when every check passed. A failed check prints what to
# do about it rather than only what went wrong.
set -uo pipefail

SERIAL=""
PACKAGE=""
PANEL="http://127.0.0.1:8722"
CANARY=1
PYTHON="${PYTHON:-python3}"
DURATION=20

while [ $# -gt 0 ]; do
  case "$1" in
    # `${2:-}` defaulted a missing value to empty, and `shift 2` on a single
    # remaining argument shifts nothing — so `--device` with no value left $1 as
    # `--device` and spun this loop forever. In a script whose whole purpose is
    # the ten minutes before a demo, a typo must not hang the terminal.
    --device)   SERIAL="${2:?--device needs a device id}";     shift 2 ;;
    --package)  PACKAGE="${2:?--package needs a package name}"; shift 2 ;;
    --panel)    PANEL="${2:?--panel needs a URL}";              shift 2 ;;
    --python)   PYTHON="${2:?--python needs a path}";           shift 2 ;;
    --no-canary) CANARY=0; shift ;;
    -h|--help)  sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1"; exit 2 ;;
  esac
done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0
FAIL=0

ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$1"; [ $# -gt 1 ] && printf '      → %s\n' "$2"; FAIL=$((FAIL + 1)); }
note() { printf '    %s\n' "$1"; }
head_() { printf '\n\033[1m%s\033[0m\n' "$1"; }

head_ "Host"

if command -v adb >/dev/null 2>&1; then
  ok "adb: $(adb version | head -1)"
else
  bad "adb is not in PATH" "export PATH=\$PATH:\$HOME/android-sdk/platform-tools"
fi

for tool in tshark editcap; do
  if command -v "$tool" >/dev/null 2>&1; then
    ok "$tool present"
  else
    bad "$tool missing — a run will capture but produce no readable summary" \
        "apt install tshark   (or: brew install wireshark)"
  fi
done

if "$PYTHON" -c 'import friTap, frida' >/dev/null 2>&1; then
  HOST_FRIDA="$("$PYTHON" -c 'import frida; print(frida.__version__)')"
  ok "friTap and frida importable ($PYTHON, frida $HOST_FRIDA)"
else
  HOST_FRIDA=""
  bad "friTap/frida not importable by $PYTHON" \
      "pip install -r requirements.txt  — or point --python at the venv that has them"
fi

head_ "Device"

if [ -z "$SERIAL" ]; then
  SERIAL="$(adb devices 2>/dev/null | awk '$2 == "device" {print $1; exit}')"
  [ -n "$SERIAL" ] && note "no --device given; using $SERIAL"
fi

STATE="$(adb -s "$SERIAL" get-state 2>/dev/null | tr -d '\r')"
if [ "$STATE" = "device" ]; then
  ok "device $SERIAL is attached and authorised"
else
  # An unauthorised device is present and useless, which is a different problem
  # from an absent one and has a different fix.
  bad "device $SERIAL is '${STATE:-not attached}'" \
      "check the cable, adb start-server, or accept the prompt on the device"
fi

if [ "$STATE" = "device" ]; then
  ABI="$(adb -s "$SERIAL" shell getprop ro.product.cpu.abi | tr -d '\r')"
  REL="$(adb -s "$SERIAL" shell getprop ro.build.version.release | tr -d '\r')"
  ok "Android $REL, $ABI"

  # Ask before elevating, and never elevate a device reached over the network.
  # `adb root` restarts adbd, which on USB costs a reconnect the server handles
  # by itself — but over TCP it drops the transport, and the device goes offline
  # and stays there until someone runs `adb connect` again. A readiness check
  # that knocks the device off the bus is worse than one that reports honestly
  # that root is missing. sockstack itself only ever detects; this now matches.
  UID_NOW="$(adb -s "$SERIAL" shell id -u 2>/dev/null | tr -d '\r')"
  case "$SERIAL" in
    *:[0-9]*) NETWORK_DEVICE=1 ;;
    *)        NETWORK_DEVICE=0 ;;
  esac
  if [ "$UID_NOW" != "0" ] && [ "$NETWORK_DEVICE" = "0" ]; then
    adb -s "$SERIAL" root >/dev/null 2>&1
    adb -s "$SERIAL" wait-for-device >/dev/null 2>&1
    UID_NOW="$(adb -s "$SERIAL" shell id -u 2>/dev/null | tr -d '\r')"
  fi
  if [ "$UID_NOW" = "0" ]; then
    ok "root shell available"
  elif [ "$(adb -s "$SERIAL" shell 'su -c id -u' 2>/dev/null | tr -d '\r')" = "0" ]; then
    ok "root through su"
  else
    bad "no root on this device — no packet capture, no /proc/net cross-check" \
        "use an emulator started without -writable-system, or a Magisk phone"
  fi

  DEV_FRIDA="$(adb -s "$SERIAL" shell '/data/local/tmp/frida-server --version' 2>/dev/null | tr -d '\r')"
  if [ -n "$DEV_FRIDA" ]; then
    if adb -s "$SERIAL" shell pidof frida-server >/dev/null 2>&1; then
      ok "frida-server $DEV_FRIDA on the device, running"
    else
      ok "frida-server $DEV_FRIDA on the device (sockstack starts it on demand)"
    fi
    if [ -n "$HOST_FRIDA" ] && [ "${DEV_FRIDA%%.*}" != "${HOST_FRIDA%%.*}" ]; then
      bad "frida major versions differ: device $DEV_FRIDA, host $HOST_FRIDA" \
          "push a frida-server matching the host, with ./setup-device.sh"
    fi
  else
    bad "no frida-server at /data/local/tmp/frida-server" \
        "./setup-device.sh $SERIAL ./frida-server-<version>-android-<arch>"
  fi

  # The same three places, in the same order, that the runner searches. Looking
  # only on PATH called a stock phone provisioned by our own setup-device.sh
  # unready — it puts the binary in /data/local/tmp, which is on no PATH — and
  # the advice printed then sent the operator to put it there a second time.
  # Read the answer, do not read the exit status: `adb shell` has not always
  # propagated one, and this script already learned that lesson on `pm list`.
  TCPDUMP_AT="$(adb -s "$SERIAL" shell 'for p in /system/bin/tcpdump /data/local/tmp/tcpdump; do [ -x "$p" ] && echo "$p"; done; command -v tcpdump' 2>/dev/null | tr -d '\r' | head -1)"
  if [ -n "$TCPDUMP_AT" ]; then
    ok "tcpdump on the device ($TCPDUMP_AT)"
  else
    bad "no tcpdump on the device — the run will have no pcap, so no decryption" \
        "./setup-device.sh $SERIAL '' ./tcpdump-static"
  fi

  if [ -n "$PACKAGE" ]; then
    # No `| grep -q` here: grep exits on the first match, adb takes SIGPIPE, and
    # under `pipefail` the whole pipeline reports failure — which reads as "not
    # installed" for a package that is. A false negative in a preflight is worse
    # than no preflight.
    PKGS="$(adb -s "$SERIAL" shell pm list packages 2>/dev/null | tr -d '\r')"
    if [[ $'\n'"$PKGS"$'\n' == *$'\n'"package:$PACKAGE"$'\n'* ]]; then
      ok "target $PACKAGE is installed"
    else
      bad "$PACKAGE is not installed on $SERIAL" "install it, or pass a --package that is"
    fi
  fi
fi

head_ "Panel"

if command -v curl >/dev/null 2>&1; then
  CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 "$PANEL/" 2>/dev/null)"
  if [ "$CODE" = "200" ]; then
    ok "web panel answering at $PANEL"
  else
    # Not fatal: the CLI is the product and the panel is optional.
    note "panel not answering at $PANEL (fine if you are demoing the CLI)"
    note "start it with:  $PYTHON ui/server.py"
  fi
fi

if [ "$CANARY" = "1" ] && [ "$STATE" = "device" ] && [ -n "$PACKAGE" ] && [ -n "$HOST_FRIDA" ]; then
  head_ "Canary run — the only check that proves the whole chain"
  OUT="$(mktemp -d /tmp/sockstack-preflight.XXXXXX)"
  note "$DURATION seconds against $PACKAGE, into $OUT"
  if "$PYTHON" "$HERE/sockstack.py" --device "$SERIAL" --package "$PACKAGE" \
       --output "$OUT" --duration "$DURATION" > "$OUT/preflight.log" 2>&1; then
    :
  fi
  SUMMARY="$(ls "$OUT"/summary_*.md 2>/dev/null | head -1)"
  RECORDS="$("$PYTHON" - "$OUT" <<'PY' 2>/dev/null
import json, os, sys
path = os.path.join(sys.argv[1], 'socket_trace.json')
print(len(json.load(open(path))) if os.path.exists(path) else 0)
PY
)"
  if [ "${RECORDS:-0}" -gt 0 ]; then
    ok "tracer recorded $RECORDS socket operation(s)"
  else
    bad "the tracer recorded nothing" \
        "the app may not have reached the network in $DURATION s — drive it, or use --attach"
  fi
  if [ -n "$SUMMARY" ]; then
    ok "summary written: $(basename "$SUMMARY")"
    if grep -q 'Java bridge: available' "$SUMMARY"; then
      ok "Java bridge available — call sites will be attributed"
    else
      bad "no Java bridge in this run — every record would come back unattributed" \
          "rebuild the agent bundle (npm run build in agent/), see docs/GOTCHAS.md"
    fi
    if [ -s "$OUT/traffic.pcap" ]; then
      ok "pcap captured ($(wc -c < "$OUT/traffic.pcap") bytes)"
    else
      bad "no pcap — decryption and the DNS/SNI sections will be empty" \
          "check tcpdump and root on the device"
    fi
  else
    bad "no summary was produced" "read $OUT/preflight.log"
    note "log tail:"
    tail -5 "$OUT/preflight.log" | sed 's/^/      /'
  fi
  rm -rf "$OUT"
elif [ "$CANARY" = "1" ]; then
  head_ "Canary run"
  note "skipped — needs a device, a --package and a working friTap"
fi

printf '\n'
if [ "$FAIL" -eq 0 ]; then
  printf '\033[32m%s checks passed. Ready.\033[0m\n' "$PASS"
  exit 0
fi
printf '\033[31m%s passed, %s failed.\033[0m Fix the ✗ lines above; each says how.\n' "$PASS" "$FAIL"
exit 1
