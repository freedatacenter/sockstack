#!/usr/bin/env python3
"""
droidtrace — Java call-stack attribution for Android network traffic.

friTap (https://github.com/fkie-cad/friTap) already solves TLS interception:
it hooks the crypto libraries, writes an NSS keylog, and defeats certificate
pinning without installing a CA. What it does not tell you is *which code path*
opened a connection. droidtrace adds exactly that, as a friTap ScriptPlugin:
every socket operation is recorded with the Java stack that produced it, so a
decrypted request can be traced back to the class and method that sent it.

Layers, so it is clear what belongs to whom:

    friTap      TLS keylog, pinning bypass, anti-root, spawn/attach, device I/O
    droidtrace  the socket tracer plugin, packet capture, decryption, summary

Two design points that exist because of how targets actually behave:

  * Records are written to disk as they arrive and every artifact is finalized
    *before* the friTap session is stopped. A target that dies early — routine
    for malware — must not take the collected evidence with it.
  * The capture is a raw `tcpdump` on the device, not friTap's synthetic
    plaintext pcap, so timestamps, ports and non-TLS traffic survive. Keys are
    injected afterwards with `editcap --inject-secrets`. Cleartext findings are
    read from the raw capture, so a run that collected no TLS keys still
    produces a useful summary rather than an empty one.

Example:
    python3 droidtrace.py --device emulator-5554 \\
        --package com.example.app --output ./run --duration 200

Requires Frida 17.x and friTap 2.x. Licensed AGPL-3.0; see NOTICE for the
origin of the instrumentation.
"""
import argparse
import binascii
import glob
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections import Counter
from datetime import datetime, timezone

__version__ = '2.2.1'

DEV_PCAP = '/data/local/tmp/droidtrace_capture.pcap'
FRIDA_SERVER = '/data/local/tmp/frida-server'
# The agent is a compiled bundle: Frida 17 removed the built-in Java bridge, so
# it has to be bundled in (see agent/ and docs/GOTCHAS.md).
DEFAULT_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              'scripts', 'frida', 'socket_trace.bundle.js')
STOP_TIMEOUT = 30
MIN_FREE_MB = 200
# The tracer emits counts every 2s while the target lives; several missed beats
# mean the process is gone.
HEARTBEAT_TIMEOUT = 10
# The summary is a report, not a dump: full bodies go to their own file.
MAX_BODIES_IN_SUMMARY = 5
BODY_PREVIEW_CHARS = 800

# Artifacts this tool owns. Moved aside at the start of a capture run so a stale
# pcap from a previous run can never be summarized as if it were this one's.
RUN_ARTIFACTS = ('traffic.pcap', 'decrypted.pcapng', 'sslkeylog.txt',
                 'socket_trace.json', 'socket_trace.jsonl',
                 'socket_trace_counts.json', 'socket_trace_meta.json',
                 'run_manifest.json')
# Reports carry the run's timestamp, so they are matched by pattern.
RUN_ARTIFACT_GLOBS = ('summary_*.md', 'decrypted_bodies_*.txt')

# Frames that are never the answer to "which code sent this".
# Kept in step with FRAMEWORK_PREFIXES in agent/src/addr.js, which uses the same
# list to decide which frames identify a call site — change one, change the other.
FRAMEWORK_PREFIXES = ('java.', 'javax.', 'android.', 'androidx.', 'libcore.',
                      'sun.', 'dalvik.', 'com.android.')
# Networking libraries: informative, but still not the calling application code.
# Without this split the "nearest application frame" is almost always
# okhttp3.internal.* rather than the class that made the request.
NETWORK_PREFIXES = ('okhttp3.', 'okio.', 'retrofit2.', 'com.squareup.',
                    'com.google.android.gms.', 'org.chromium.', 'io.grpc.',
                    'io.netty.', 'org.apache.http', 'org.conscrypt.',
                    'com.google.firebase.')

# Why a peer can carry no call-stack attribution, in precedence order: when a
# peer's records disagree, the report shows the reason that concedes the most
# ignorance. Presenting a destination we never examined as "native code" is a
# confident wrong answer, and for an investigation that is worse than no answer
# — so "we did not look" always outranks "there was nothing to see".
UNATTRIBUTED_REASONS = (
    ('attribution-unavailable',
     'the Java bridge was not working, so attribution was impossible here — '
     'this is not evidence that the call site is native'),
    ('unknown',
     'the tracer did not record why there is no stack — treat as unexamined'),
    ('not-examined',
     'never stack-walked: the per-destination budget was already spent on '
     'other call sites, so further callers may exist'),
    ('framework-only',
     'a Java stack was captured, but it contains only framework frames and so '
     'does not name the calling code'),
    ('native-thread',
     'genuinely native: the calling thread had no JVM attached — Cronet, JNI '
     'or a non-JVM runtime'),
    ('no-runtime',
     'the process has no Java runtime at all'),
)
_REASON_ORDER = {name: index for index, (name, _) in enumerate(UNATTRIBUTED_REASONS)}
# stack_source values the tracer emits, mapped to the reason shown in the report.
# 'java' is absent on purpose: it is decided by whether the stack names any
# application code, which the mapping cannot know.
_SOURCE_TO_REASON = {
    'not-walked': 'not-examined',
    'no-bridge': 'attribution-unavailable',
    'stack-error': 'attribution-unavailable',
    'native-thread': 'native-thread',
    'no-runtime': 'no-runtime',
}

# tshark says one of these when a display filter names a field this build does
# not have. Matched rather than guessed at, because the wording varies by version.
UNKNOWN_FIELD_RE = re.compile(
    r'is neither a field nor a protocol|'
    r"isn'?t a valid|aren'?t valid|Unknown (?:display filter|field)",
    re.IGNORECASE)

_CAPTURE = {}


def run_artifacts(out_dir):
    """Every file in out_dir that belongs to a droidtrace run."""
    names = [n for n in RUN_ARTIFACTS if os.path.exists(os.path.join(out_dir, n))]
    for pattern in RUN_ARTIFACT_GLOBS:
        names += sorted(os.path.basename(p)
                        for p in glob.glob(os.path.join(out_dir, pattern)))
    return names


# --------------------------------------------------------------------------- shell helpers

def adb(serial, *cmd, timeout=60):
    """Run an adb command. A wedged device must not hang the whole run."""
    try:
        return subprocess.run(['adb', '-s', serial] + list(cmd),
                              capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f'[!] adb timed out after {timeout}s: {" ".join(cmd)}')
        return subprocess.CompletedProcess(cmd, 1, '', 'timeout')
    except FileNotFoundError:
        sys.exit('[!] adb not found in PATH')


def run(cmd, timeout=300):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f'[!] timed out after {timeout}s: {" ".join(cmd)}')
        return subprocess.CompletedProcess(cmd, 1, '', 'timeout')


# The way to gain root differs: an emulator/userdebug build answers `adb root`
# and its shell is already root, while a physical phone with Magisk only
# exposes root through `su -c`. Detect once and cache.
_PRIV = {'mode': None}


def detect_privilege(serial):
    if _PRIV['mode']:
        return _PRIV['mode']
    if (adb(serial, 'shell', 'id -u').stdout or '').strip() == '0':
        _PRIV['mode'] = 'root-shell'
    elif (adb(serial, 'shell', 'su -c id -u').stdout or '').strip() == '0':
        _PRIV['mode'] = 'su'
    else:
        _PRIV['mode'] = 'none'
    print(f'[+] device privilege: {_PRIV["mode"]}')
    return _PRIV['mode']


def priv(serial, shell_cmd, **kw):
    if detect_privilege(serial) == 'su':
        shell_cmd = f'su -c {shlex.quote(shell_cmd)}'
    return adb(serial, 'shell', shell_cmd, **kw)


def priv_background(serial, shell_cmd):
    if detect_privilege(serial) == 'su':
        shell_cmd = f'su -c {shlex.quote(shell_cmd)}'
    subprocess.Popen(['adb', '-s', serial, 'shell', shell_cmd],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def device_has(serial, shell_cmd):
    """Probe with an explicit marker instead of parsing human-readable output."""
    return '__DT_OK__' in (priv(serial, f'{shell_cmd} && echo __DT_OK__').stdout or '')


# --------------------------------------------------------------------------- plugin

def build_plugin(script_path, jsonl_path=None):
    """Construct the ScriptPlugin. Imported lazily so that --postprocess-only
    works on a machine without friTap installed."""
    from friTap.plugins import ScriptPlugin, ScriptLoadOrder

    with open(script_path) as fh:
        source = fh.read()

    class SocketTracePlugin(ScriptPlugin):
        """Injects the compiled socket tracer and collects its records.

        friTap's own `on_message()` callback is for decrypted chat messages, not
        for plugin scripts — plugin output arrives here, via on_script_message().
        Counts and metadata arrive on the same channel, so nothing here has to
        touch friTap's private plugin internals.

        Every record is also appended to a JSONL file the moment it arrives. If
        the target dies and the process is torn down before the normal
        finalization, that file is still on disk and complete.
        """

        def __init__(self):
            super().__init__()
            self.records = []
            self.counts = None
            self.meta = {}
            self.errors = []
            self.warnings = []
            # The script emits a counts message on a timer for as long as the
            # process lives, which doubles as a heartbeat. friTap's is_running
            # tracks its own logger, not the target, so it never goes false when
            # the app dies.
            self.last_message = None
            self._sink = open(jsonl_path, 'a') if jsonl_path else None

        @property
        def name(self):
            return 'droidtrace-socket-trace'

        @property
        def version(self):
            return __version__

        @property
        def load_order(self):
            return ScriptLoadOrder.AFTER_MAIN

        def get_script_source(self, context):
            return source

        def close_sink(self):
            if self._sink:
                self._sink.flush()
                self._sink.close()
                self._sink = None

        def on_script_message(self, message, data):
            self.last_message = time.monotonic()
            if message.get('type') == 'error':
                detail = message.get('description') or message
                self.errors.append(str(detail))
                print(f'\n[script error] {detail}')
                return
            payload = message.get('payload')
            if not isinstance(payload, dict):
                return
            kind = payload.get('type')
            if kind == 'socket_trace_log':
                record = payload['data']
                self.records.append(record)
                if self._sink:
                    self._sink.write(json.dumps(record) + '\n')
                    self._sink.flush()
            elif kind == 'socket_trace_counts':
                self.counts = payload['data']
            elif kind == 'socket_trace_ready':
                # Hooks are live before this message is sent, so a warning can
                # arrive first; merging keeps both.
                self.meta = {**self.meta, **payload['data']}
                print(f'[+] socket tracer active on {payload["data"]["libc"]}: '
                      f'{", ".join(sorted(payload["data"]["hooked"]))}')
                missing = payload['data'].get('missing')
                if missing:
                    print(f'[!] not hooked (absent from this libc): {", ".join(sorted(missing))}')
            elif kind == 'socket_trace_error':
                detail = payload['data'].get('error')
                self.errors.append(str(detail))
                # Merged, never assigned: the ready message carries the hook list
                # and bridge state, and losing it to whichever message happens to
                # arrive last would leave the run undiagnosable.
                self.meta = {**self.meta, **payload['data']}
                print(f'[!] socket tracer failed to install: {detail}')
            elif kind == 'socket_trace_warning':
                detail = payload['data'].get('warning')
                self.warnings.append(str(detail))
                self.meta = {**self.meta, **payload['data']}
                print(f'[!] socket tracer warning: {detail}')

    return SocketTracePlugin()


# --------------------------------------------------------------------------- preflight

def frida_major():
    import frida
    try:
        return int(str(frida.__version__).split('.')[0])
    except (ValueError, IndexError, AttributeError):
        return None


def device_present(serial, adb_devices_output):
    """Exact match on the device list. A substring test would confuse
    emulator-5554 with emulator-55540."""
    for line in (adb_devices_output or '').splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[0] == serial:
            return parts[1]
    return None


def preflight(args):
    """Fail before the run rather than in the middle of it."""
    problems = []

    if not args.host:
        if not shutil.which('adb'):
            problems.append('adb not found in PATH')
        else:
            state = device_present(args.device, run(['adb', 'devices']).stdout)
            if state is None:
                problems.append(f'device {args.device!r} not in `adb devices`')
            elif state != 'device':
                problems.append(f'device {args.device!r} is in state {state!r}, not "device"')

    try:
        import frida
        major = frida_major()
        if major is None:
            print(f'[!] cannot parse the Frida version ({frida.__version__!r}) — '
                  f'continuing, but friTap 2.x expects 17.x')
        elif major != 17:
            problems.append(f'Frida {frida.__version__}: this tool is built against 17.x '
                            f'(pip install -r requirements.txt)')
    except ImportError:
        problems.append('frida not installed (pip install -r requirements.txt)')

    try:
        import friTap
        version = getattr(friTap, '__version__', None)
        if version:
            try:
                if int(str(version).split('.')[0]) != 2:
                    problems.append(f'friTap {version}: this tool is built against 2.x '
                                    f'(the plugin API differs elsewhere)')
            except (ValueError, IndexError):
                pass
    except ImportError:
        problems.append('friTap not installed (pip install -r requirements.txt)')

    if not os.path.exists(args.script):
        problems.append(f'tracer script not found: {args.script}')

    if not args.no_postprocess:
        missing = [t for t in ('editcap', 'tshark') if not shutil.which(t)]
        if missing:
            print(f'[!] {", ".join(missing)} not found — decryption and the traffic '
                  f'summary will be skipped. Install wireshark-cli to enable them.')

    if problems:
        for p in problems:
            print(f'[!] {p}')
        sys.exit(1)


# --------------------------------------------------------------------------- device setup

def frida_server_alive(serial, device_id):
    """A hard-killed frida-server can linger as a corpse, so probe the API too."""
    import frida
    if not (priv(serial, f'pidof {os.path.basename(FRIDA_SERVER)}').stdout or '').strip():
        return False
    try:
        frida.get_device(device_id).enumerate_processes()
        return True
    except Exception:
        return False


def ensure_frida_server(serial, device_id):
    if detect_privilege(serial) == 'none':
        print('[!] no root on the device — Frida cannot hook. '
              'Emulator: `adb -s <id> root`. Phone: Magisk required.')
        return False
    if frida_server_alive(serial, device_id):
        print('[+] frida-server responding')
        return True
    print('[!] frida-server dead or unresponsive — restarting it '
          '(this kills any other frida-server session on this device)')
    priv(serial, f'pkill -f {os.path.basename(FRIDA_SERVER)}')
    time.sleep(2)
    if not device_has(serial, f'test -x {shlex.quote(FRIDA_SERVER)}'):
        print(f'[!] {FRIDA_SERVER} is missing or not executable. Push a frida-server '
              f'17.x matching the device architecture:\n'
              f'    ./setup-device.sh {serial} ./frida-server-17.x.y-android-arm64')
        return False
    priv_background(serial, f'nohup {FRIDA_SERVER} --daemonize >/dev/null 2>&1 &')
    for _ in range(10):
        time.sleep(2)
        if frida_server_alive(serial, device_id):
            print('[+] frida-server up')
            return True
    print('[!] could not bring frida-server up')
    return False


def find_tcpdump(serial, explicit=None):
    """Emulator images ship tcpdump in /system/bin; a stock phone has none."""
    for path in ([explicit] if explicit else []) + ['/system/bin/tcpdump',
                                                   '/data/local/tmp/tcpdump']:
        if device_has(serial, f'test -x {shlex.quote(path)}'):
            return path
    if device_has(serial, 'command -v tcpdump >/dev/null'):
        return 'tcpdump'
    return None


def device_free_mb(serial):
    out = (priv(serial, 'df -k /data/local/tmp | tail -1').stdout or '').split()
    for token in reversed(out):
        if token.isdigit():
            return int(token) // 1024
    return None


def start_capture(serial, tcpdump_path=None):
    binary = find_tcpdump(serial, tcpdump_path)
    if not binary:
        print('[!] no tcpdump on the device — no pcap will be produced. Push a static '
              'binary with ./setup-device.sh, or pass --tcpdump <path>.')
        return False
    free = device_free_mb(serial)
    if free is not None and free < MIN_FREE_MB:
        print(f'[!] only {free} MB free on /data — a long capture may fill the '
              f'partition. Shorten --duration or free space.')
    print(f'[+] tcpdump: {binary}')
    # Match on the output path so only this tool's capture is killed, not an
    # unrelated tcpdump the analyst is running.
    priv(serial, f'pkill -f {shlex.quote(DEV_PCAP)}')
    priv(serial, f'rm -f {DEV_PCAP}')
    # Write to a file ON the device. Streaming through `adb exec-out` mixes
    # tcpdump's stderr into the binary stdout and corrupts the pcap.
    priv_background(serial, f'nohup {shlex.quote(binary)} -U -n -i any -w {DEV_PCAP} '
                            f'>/dev/null 2>&1 &')
    _CAPTURE['binary'] = binary
    time.sleep(3)
    pid = (priv(serial, f'pidof {os.path.basename(binary)}').stdout or '').strip()
    print(f'[+] capture started: pid={pid or "FAILED TO START"}')
    return bool(pid)


def stop_capture(serial, out_dir, keep_device_artifacts=False):
    if not _CAPTURE.pop('binary', None):
        return None
    priv(serial, f'pkill -INT -f {shlex.quote(DEV_PCAP)}')
    time.sleep(2)
    dst = os.path.join(out_dir, 'traffic.pcap')
    # The capture is root-owned and adb pull runs as the shell user, so it has to
    # be made readable first. That briefly exposes it to anything else on the
    # device, which is why it is removed again below.
    priv(serial, f'chmod 644 {DEV_PCAP}')
    result = adb(serial, 'pull', DEV_PCAP, dst, timeout=300)
    pulled = result.returncode == 0 and os.path.exists(dst)
    if pulled:
        print(f'[+] pcap: {dst} ({os.path.getsize(dst)} bytes)')
    else:
        print(f'[!] failed to pull the pcap: {(result.stderr or "").strip()[:200]}')

    if keep_device_artifacts:
        print(f'[!] leaving {DEV_PCAP} on the device (--keep-device-artifacts): '
              f'it is world-readable and holds raw traffic')
    elif pulled:
        priv(serial, f'rm -f {DEV_PCAP}')
    else:
        print(f'[!] not deleting {DEV_PCAP} — the pull failed and it is the only copy. '
              f'Retrieve it by hand, then remove it.')
    return dst if pulled else None


# --------------------------------------------------------------------------- analysis (pure)

def classify_stack(stack):
    """Split a Java stack into application frames and networking-library frames.

    Returning both matters: the innermost non-framework frame is usually
    okhttp3/Cronet, not the code that made the request.
    """
    app, network = [], []
    for frame in stack or []:
        if not isinstance(frame, dict):
            continue
        text = frame.get('str') or frame.get('class') or ''
        if not text:
            continue
        if text.startswith(NETWORK_PREFIXES):
            network.append(text)
        elif not text.startswith(FRAMEWORK_PREFIXES):
            app.append(text)
    return app, network


def format_peer(ip, port):
    """`1.2.3.4:443`, but `[2a02:...::1]:443` — a bare IPv6 literal followed by a
    colon and a port is unreadable and ambiguous."""
    ip = str(ip)
    return f'[{ip}]:{port}' if ':' in ip else f'{ip}:{port}'


def aggregate_counts(counts):
    """Fold the tracer's counters into (peer, operation) totals."""
    totals = Counter()
    for key, hits in (counts or {}).items():
        parts = key.split('|')
        if len(parts) < 3:
            continue
        operation, ip, port = parts[0], parts[1], parts[2]
        totals[f'{format_peer(ip, port)} {operation}'] += hits
    return totals


def tracer_ips(records, counts=None):
    """Every address the traced process itself contacted.

    The packet capture is device-wide, so a hostname in it proves only that
    *something* on the device resolved or contacted it. Intersecting with this
    set is what separates the target's traffic from the neighbours'.
    """
    found = set()
    for rec in records or []:
        ip = rec.get('peer_ip')
        if ip:
            found.add(str(ip))
    for key in (counts or {}):
        parts = key.split('|')
        if len(parts) >= 3 and parts[1]:
            found.add(parts[1])
    return found


def unattributed_reason(rec):
    """Why this record carries no usable call stack.

    Read from the tracer's own `stack_source`, never inferred from the absence
    of frames. The tracer is the only party that knows whether it looked, and a
    record whose stack is missing because nobody walked it must not be
    presented as one whose call site is native.
    """
    source = rec.get('stack_source')
    if source == 'java':
        return 'framework-only'      # a genuine stack, just not a naming one
    return _SOURCE_TO_REASON.get(source, 'unknown')


def disambiguate_attribution(attribution):
    """Make entries that really are different look different.

    Entries are deduplicated by the agent's stack signature, so two of them can
    render identically — same peer, same displayed frames — and still be
    distinct call sites, differing either deeper in the application code than
    the display shows or further down the library chain. Two identical-looking
    lines read as an accidental duplicate, which invites the reader to discount
    one of two real findings. Show the first frame that actually differs.
    """
    def extend(members, key, chains, shown):
        start = max(shown, 1)
        for depth in range(start, max((len(c) for c in chains), default=0)):
            level = [c[depth] if depth < len(c) else None for c in chains]
            if len(set(level)) > 1:
                for item, frame in zip(members, level):
                    if frame:
                        item[key] = ((item[key] + [frame]) if key == 'app_frames'
                                     else f'{item[key]} → {frame}')
                return True
        return False

    groups = {}
    for item in attribution:
        groups.setdefault(
            (item['peer'], tuple(item['app_frames']), item['via']), []).append(item)
    for members in groups.values():
        if len(members) < 2:
            continue
        shown = len(members[0]['app_frames'])
        if extend(members, 'app_frames',
                  [item.get('app_chain') or [] for item in members], shown):
            continue
        extend(members, 'via', [item.get('via_chain') or [] for item in members], 1)
    return attribution


def summarize_trace(records, counts=None, max_frames=3):
    """Build the peer table, the attribution table and the unattributed buckets.

    Returns (peers, attribution, unattributed, partly_examined), where
    `unattributed` maps a reason from UNATTRIBUTED_REASONS to the peers it
    applies to. A peer attributed anywhere never appears there at all;
    `partly_examined` lists peers that are attributed but still have operations
    nobody walked, so the reader knows the list of call sites may be short.
    """
    peers = aggregate_counts(counts)
    attribution = []
    seen = set()
    attributed = set()
    reasons = {}
    unexamined = set()

    for rec in records or []:
        ip = rec.get('peer_ip') or ''
        if not ip:
            continue
        peer = format_peer(ip, rec.get('peer_port'))
        if not counts:
            peers[f'{peer} {rec.get("socket_event_type")}'] += 1
        app, network = classify_stack(rec.get('stack'))
        if not app and not network:
            reason = unattributed_reason(rec)
            if reason == 'not-examined':
                unexamined.add(peer)
            current = reasons.get(peer)
            if current is None or _REASON_ORDER[reason] < _REASON_ORDER[current]:
                reasons[peer] = reason
            continue
        attributed.add(peer)
        # Deduplicate on the agent's own signature. The runner used to rebuild a
        # key from the classified frames — application frames plus only the
        # *first* library frame — which quietly disagreed with the agent, whose
        # signature covers every non-framework frame. Two call sites differing
        # deeper inside okhttp were two records to the agent and one line here,
        # so the report undercounted the very number this tool exists to give.
        # One definition, and it belongs to the side that captured the stack.
        signature = rec.get('stack_signature')
        if signature is None:            # artifacts captured before 2.2.1
            signature = (tuple(app), tuple(network))
        key = (peer, signature)
        if key in seen:
            continue
        seen.add(key)
        attribution.append({'peer': peer,
                            'app_frames': app[:max_frames],
                            'app_chain': app,
                            'via': network[0] if network else None,
                            'via_chain': network})

    disambiguate_attribution(attribution)
    unattributed = {}
    for name, _ in UNATTRIBUTED_REASONS:
        members = sorted(peer for peer, reason in reasons.items()
                         if reason == name and peer not in attributed)
        if members:
            unattributed[name] = members
    return peers, attribution, unattributed, sorted(unexamined & attributed)


# --------------------------------------------------------------------------- post-processing

def tshark_fields(path, display_filter, *names):
    """Return (rows, error). An error is not the same as an empty result, and
    conflating them is how a summary silently goes blank on a tshark upgrade."""
    if not path or not os.path.exists(path):
        return [], None
    if not shutil.which('tshark'):
        return [], 'tshark not installed'
    cmd = ['tshark', '-r', path, '-Y', display_filter, '-T', 'fields']
    for n in names:
        cmd += ['-e', n]
    r = run(cmd)
    if r.returncode != 0:
        detail = (r.stderr or '').strip()
        # An older tshark simply not knowing a field is a capability gap, not a
        # problem with the capture. Reporting it as an "analysis problem" sends
        # the analyst looking for a fault in the evidence; the caller already
        # falls back to a coarser filter when the result is empty.
        if UNKNOWN_FIELD_RE.search(detail):
            return [], None
        return [], f'tshark failed on {display_filter!r}: {detail[:120]}'
    return [line for line in r.stdout.splitlines() if line.strip()], None


def inject_secrets(pcap, keys, pcapng):
    """Return (decrypted, status_message)."""
    if not shutil.which('editcap'):
        return False, 'not attempted: editcap is not installed'
    if not os.path.exists(pcap):
        return False, 'not attempted: no traffic.pcap in this directory'
    if not os.path.exists(keys) or os.path.getsize(keys) == 0:
        return False, 'not attempted: no TLS keys were captured'
    r = run(['editcap', '--inject-secrets', f'tls,{keys}', pcap, pcapng])
    if r.returncode == 0 and os.path.exists(pcapng):
        return True, 'keys injected into the capture'
    return False, f'editcap failed: {(r.stderr or "").strip()[:160]}'


def body_rank(text):
    """Order bodies by investigative value. An API response tells you what the app
    is exfiltrating; a page of stylesheet does not, and left unsorted it buries
    the former under the latter."""
    head = text.lstrip()[:200]
    lowered = head.lower()
    if head.startswith(('{', '[')):
        return 0                                   # JSON
    if head.startswith('<?xml') or lowered.startswith('<soap'):
        return 1
    if lowered.startswith('<!doctype html') or '<html' in lowered:
        return 3                                   # markup: bulky, rarely the point
    if '{' in head and ('}' in head or ':' in head) and 'font' in lowered:
        return 4                                   # stylesheet
    return 2


def extract_bodies(hex_rows):
    """Decode tshark's hex payload rows into distinct bodies, most interesting
    first. De-duplication is by content hash: the same body arrives once per
    HTTP/2 DATA frame group and would otherwise be repeated verbatim."""
    seen = set()
    bodies = []
    for hexline in hex_rows:
        try:
            raw = binascii.unhexlify(hexline.strip().replace(':', ''))
        except binascii.Error:
            continue
        if not raw:
            continue
        fingerprint = hashlib.sha256(raw).hexdigest()
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        bodies.append(raw.decode('utf-8', 'replace'))
    return sorted(bodies, key=body_rank)


def _load_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path) as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return default


def split_row(row, count):
    """tshark -T fields joins columns with tabs and omits trailing empties."""
    parts = row.split('\t')
    parts += [''] * (count - len(parts))
    return parts[:count]


def first_addr(*candidates):
    for value in candidates:
        if value:
            return value.split(',')[0].strip()
    return ''


def _load_records(out_dir):
    """Prefer the finalized array; fall back to the incremental log, which is
    what survives if a run was cut short."""
    records = _load_json(os.path.join(out_dir, 'socket_trace.json'), None)
    if records is not None:
        return records
    jsonl = os.path.join(out_dir, 'socket_trace.jsonl')
    if not os.path.exists(jsonl):
        return []
    out = []
    with open(jsonl) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def run_stamp(out_dir, explicit=None):
    """A compact, sortable UTC stamp for report filenames. Prefer the recorded
    start of the capture so the report is named after the run it describes, not
    after whenever it happened to be regenerated."""
    if explicit is not None:
        return explicit.strftime('%Y%m%dT%H%M%SZ')
    started = _load_json(os.path.join(out_dir, 'run_manifest.json'), {}).get('started_utc')
    if started:
        try:
            return datetime.fromisoformat(started).strftime('%Y%m%dT%H%M%SZ')
        except ValueError:
            pass
    return datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')


def decrypt_and_summarize(out_dir, target, target_is_recorded=False, stamp=None):
    if not os.path.isdir(out_dir):
        print(f'[!] {out_dir} is not a directory — nothing to post-process')
        return
    pcap = os.path.join(out_dir, 'traffic.pcap')
    keys = os.path.join(out_dir, 'sslkeylog.txt')
    pcapng = os.path.join(out_dir, 'decrypted.pcapng')
    issues = []

    decrypted, decrypt_status = inject_secrets(pcap, keys, pcapng)
    print(f'[{"+" if decrypted else "!"}] decryption: {decrypt_status}')
    enc = pcapng if decrypted else None

    def collect(path, flt, *fields):
        rows, err = tshark_fields(path, flt, *fields)
        if err:
            issues.append(err)
        return rows

    records = _load_records(out_dir)
    counts_blob = _load_json(os.path.join(out_dir, 'socket_trace_counts.json'), {})
    meta = _load_json(os.path.join(out_dir, 'socket_trace_meta.json'), {})
    peers, attribution, unattributed, partly_examined = summarize_trace(
        records, counts_blob.get('counts'))
    stack_sources = Counter(r.get('stack_source') or 'unknown' for r in records)
    # Addresses the traced process actually talked to. The capture is device-wide,
    # so this set is the only thing that ties a packet-derived finding to the
    # target rather than to whatever else the device was doing.
    target_ips = tracer_ips(records, counts_blob.get('counts'))

    # Cleartext lives in the raw capture and needs no keys at all. Reading it
    # from there is what keeps a keyless run useful instead of empty.
    sni, sni_target = Counter(), set()
    for row in collect(pcap, 'tls.handshake.extensions_server_name',
                       'tls.handshake.extensions_server_name', 'ip.dst', 'ipv6.dst'):
        name, ip4, ip6 = split_row(row, 3)
        if not name:
            continue
        sni[name] += 1
        if first_addr(ip4, ip6) in target_ips:
            sni_target.add(name)

    # Map query names to answers so a DNS lookup can be tied to the target by the
    # address it resolved to.
    name_to_ips = {}
    for row in collect(pcap, 'dns.flags.response == 1', 'dns.qry.name',
                       'dns.a', 'dns.aaaa'):
        name, a, aaaa = split_row(row, 3)
        if not name:
            continue
        answers = {v.strip() for v in (a + ',' + aaaa).split(',') if v.strip()}
        name_to_ips.setdefault(name, set()).update(answers)

    dns = Counter(collect(pcap, 'dns.flags.response == 0', 'dns.qry.name'))
    dns_target = {name for name in dns
                  if name_to_ips.get(name, set()) & target_ips}

    def http_rows(path, flt, *fields):
        out = {}
        for row in collect(path, flt, *(fields + ('ip.dst', 'ipv6.dst'))):
            cols = split_row(row, len(fields) + 2)
            label = ' '.join(part for part in cols[:len(fields)] if part)
            if not label:
                continue
            out[label] = out.get(label, False) or \
                first_addr(cols[-2], cols[-1]) in target_ips
        return out

    http1 = http_rows(pcap, 'http.request', 'http.host',
                      'http.request.method', 'http.request.uri')
    for label, is_target in http_rows(enc, 'http.request', 'http.host',
                                      'http.request.method',
                                      'http.request.uri').items():
        http1[label] = http1.get(label, False) or is_target
    http2 = http_rows(enc, 'http2.headers', 'http2.headers.authority',
                      'http2.headers.method', 'http2.headers.path')

    # Reassembled bodies are whole messages; http2.data.data yields one row per
    # DATA frame, so a body arrives as fragments that start mid-token. Prefer the
    # former and say so when falling back, rather than presenting fragments as
    # if they were complete payloads.
    body_rows = collect(enc, 'http2.body.reassembled.data',
                        'http2.body.reassembled.data')
    fragmented = False
    if not body_rows:
        body_rows = collect(enc, 'http2.data.data', 'http2.data.data')
        fragmented = bool(body_rows)
    body_rows += collect(pcap, 'http.file_data', 'http.file_data')
    body_rows += collect(enc, 'http.file_data', 'http.file_data')

    stamp = run_stamp(out_dir, stamp)
    bodies_name = f'decrypted_bodies_{stamp}.txt'
    bodies = extract_bodies(body_rows)
    bodies_path = None
    if bodies:
        bodies_path = os.path.join(out_dir, bodies_name)
        with open(bodies_path, 'w') as out:
            for i, body in enumerate(bodies, 1):
                out.write(f'----- body {i}/{len(bodies)} ({len(body)} chars) -----\n')
                out.write(body + '\n\n')
        print(f'[+] decrypted bodies: {bodies_path} ({len(bodies)})')

    def mark(is_target):
        """Distinguish the target's own traffic from everything else the device
        was doing. Without this the analyst has to guess, and guesses wrong."""
        return ' — **target**' if is_target else ' — other process'

    # The header must name what was actually analysed. Under --postprocess-only
    # the caller can pass any label, so the recorded target wins over it.
    manifest = _load_json(os.path.join(out_dir, 'run_manifest.json'), {})
    recorded = manifest.get('target')
    heading = target if target_is_recorded else (recorded or target)
    lines = [f'# droidtrace run: {heading}', '',
             f'Report generated: {datetime.now(timezone.utc).isoformat(timespec="seconds")}',
             '', f'Artifacts: `{out_dir}`', '']
    if not target_is_recorded:
        if recorded and target and target != recorded:
            lines += [f'_Label given on the command line was `{target}`; the target '
                      f'above is the one recorded in `run_manifest.json` when the '
                      f'capture ran._', '']
        elif not recorded:
            lines += ['_No `run_manifest.json` here, so the target above is the label '
                      'passed to `--postprocess-only`, not a recorded fact._', '']
    lines += ['## Run status', '',
              f'- Tracer records: {len(records)}',
              f'- Decryption: {decrypt_status}']
    if meta.get('hooked'):
        lines.append(f'- Hooked: {", ".join(sorted(meta["hooked"]))}')
    if meta.get('missing'):
        lines.append(f'- Not present in libc: {", ".join(sorted(meta["missing"]))}')
    if meta.get('error'):
        lines.append(f'- **Tracer problem: {meta["error"]}**')
    for warning in meta.get('warnings') or []:
        lines.append(f'- **Tracer warning: {warning}**')
    if counts_blob.get('stack_errors'):
        lines.append(f'- **Stack walks that threw: {counts_blob["stack_errors"]}** '
                     f'({counts_blob.get("stack_error_sample") or "no detail"}) — '
                     f'those records are unattributed for that reason, not because '
                     f'the call site was native.')
    if meta.get('android_runtime') is not None:
        if meta.get('android_runtime') and meta.get('java_bridge'):
            lines.append('- Java bridge: available (call-stack attribution active)')
        elif meta.get('android_runtime'):
            lines.append(f'- **Java bridge: NOT available** '
                         f'({meta.get("java_bridge_error") or "unknown"}) — every record '
                         f'below is unattributed for that reason, not because the '
                         f'traffic was native.')
        else:
            lines.append('- Java bridge: not applicable (no Android runtime in this process)')
    if stack_sources:
        # Split `java` into the two outcomes it actually covers. Otherwise the
        # status line says java=16 while a peer appears below under
        # "framework-only", and the reader stops to work out whether the numbers
        # disagree — they never did, but the line was hiding a distinction the
        # section below makes.
        framework_only = sum(
            1 for r in records
            if r.get('stack_source') == 'java' and not any(classify_stack(r.get('stack')))
        )
        parts = []
        for key, value in sorted(stack_sources.items()):
            if key == 'java' and framework_only:
                parts.append(f'java={value} ({value - framework_only} naming app '
                             f'code, {framework_only} framework-only)')
            else:
                parts.append(f'{key}={value}')
        lines.append('- Record stack sources: ' + ', '.join(parts))
    if counts_blob.get('truncated'):
        lines.append(f'- **Event cap ({counts_blob.get("max_events")}) reached** — '
                     f'counts remain complete, but call sites first seen after the '
                     f'cap have no stored record.')
    for issue in issues:
        lines.append(f'- Analysis problem: {issue}')
    if not records and not os.path.exists(pcap):
        lines.append('- No tracer records and no capture: this run collected nothing.')

    lines += ['', '## Peers (socket tracer — pre-DNS, pre-TLS)', '']
    lines += [f'- `{k}` — {v}' for k, v in peers.most_common()] or ['- (none)']

    lines += ['', '## Call-stack attribution', '']
    if attribution:
        for item in attribution:
            frames = ', '.join(f'`{f}`' for f in item['app_frames']) or '(library only)'
            via = f' — via `{item["via"]}`' if item['via'] else ''
            lines.append(f'- `{item["peer"]}` ← {frames}{via}')
    else:
        lines.append('- (none)')
    if partly_examined:
        lines += ['',
                  'Attributed above, but not exhaustively: some operations to these '
                  'peers were never stack-walked, so further call sites may exist.', '']
        lines += [f'- `{p}`' for p in partly_examined]
    for name, why in UNATTRIBUTED_REASONS:
        members = unattributed.get(name)
        if not members:
            continue
        lines += ['', f'Unattributed — {why}:', '']
        lines += [f'- `{p}`' for p in members]

    lines += ['', '---', '',
              '_Everything above comes from the tracer and describes the target '
              'process only. Everything below is read from the packet capture, which '
              'is device-wide. Each entry is marked **target** when its address is one '
              'the tracer saw the target contact, and "other process" when it is not — '
              'an unmarked host was resolved or contacted by something else on the '
              'device, not by the app under analysis._', '']
    lines += ['', '## DNS queries', '']
    lines += [f'- `{n}` — {c}{mark(n in dns_target)}'
              for n, c in dns.most_common()] or ['- (none)']
    lines += ['', '## SNI', '']
    lines += [f'- `{n}` — {c}{mark(n in sni_target)}'
              for n, c in sni.most_common()] or ['- (none)']
    lines += ['', '## HTTP/1 requests', '']
    lines += [f'- `{r}`{mark(http1[r])}' for r in sorted(http1)] or ['- (none)']
    lines += ['', '## HTTP/2 requests', '']
    lines += [f'- `{r}`{mark(http2[r])}' for r in sorted(http2)] or ['- (none)']
    lines += ['', '## Decrypted bodies', '']
    if bodies:
        shown = bodies[:MAX_BODIES_IN_SUMMARY]
        note = (' These are individual DATA frames, not reassembled messages — '
                'Wireshark could not reassemble them, so a single body may appear '
                'split across several entries.') if fragmented else ''
        noun = 'body' if len(bodies) == 1 else 'distinct bodies'
        scope = ('truncated to %d characters' % BODY_PREVIEW_CHARS) if \
            any(len(b) > BODY_PREVIEW_CHARS for b in shown) else 'in full'
        lines += [f'{len(bodies)} {noun}; showing {len(shown)}, API-style payloads '
                  f'first, {scope}. Full text: `{bodies_name}`. Full session: '
                  f'`decrypted.pcapng`.{note}',
                  '']
        for i, body in enumerate(shown, 1):
            clipped = body[:BODY_PREVIEW_CHARS]
            suffix = ' …truncated' if len(body) > BODY_PREVIEW_CHARS else ''
            lines += [f'**Body {i}** ({len(body)} chars){suffix}', '',
                      '```', clipped, '```', '']
    else:
        lines += ['- (none)', '']

    summary = os.path.join(out_dir, f'summary_{stamp}.md')
    with open(summary, 'w') as out:
        out.write('\n'.join(lines) + '\n')
    print(f'[+] summary: {summary}')
    print(f'    peers: {len(peers)}, attributed call sites: {len(attribution)}, '
          f'DNS: {len(dns)}, SNI: {len(sni)}, '
          f'HTTP requests: {len(http1) + len(http2)}')
    if issues:
        print(f'[!] {len(issues)} analysis problem(s) recorded in {os.path.basename(summary)}')


# --------------------------------------------------------------------------- provenance

def file_digest(path):
    """sha256 of a file, or None if it is not there."""
    if not path or not os.path.exists(path):
        return None
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()



def suggest_process_names(args):
    """Print what Frida actually calls the running processes.

    Attaching by package name looks obvious and quietly fails: Frida names the
    main process of a foreground app by its *label*, so a running
    `com.android.chrome` is offered as `Chrome` and `--package
    com.android.chrome` reports "unable to find process" while the app is
    plainly on screen. Guessing wastes an analyst's time, so show the list.
    """
    if args.host:
        return
    try:
        import frida
        device = frida.get_device(args.device, timeout=5) if args.device \
            else frida.get_usb_device(timeout=5)
        processes = device.enumerate_processes()
    except Exception as exc:
        print(f'    (could not list processes on the device: {exc})')
        return
    needle = (args.package or '').lower()
    stem = needle.rsplit('.', 1)[-1]
    likely = [p for p in processes
              if needle in p.name.lower() or (stem and stem in p.name.lower())]
    if likely:
        print('    Frida knows these processes by a different name — try one of:')
        for proc in likely[:10]:
            print(f'      --package "{proc.name}"    (pid {proc.pid})')
    else:
        print(f'    Frida sees {len(processes)} processes on the device and none '
              f'matches "{args.package}". List them with:')
        print(f'      frida-ps -D {args.device or "<device>"}')

def write_manifest(out_dir, args, plugin, started, ended, stop_clean):
    def digest(name):
        return file_digest(os.path.join(out_dir, name))

    versions = {'droidtrace': __version__}
    for mod in ('frida', 'friTap'):
        try:
            versions[mod] = getattr(__import__(mod), '__version__', 'unknown')
        except ImportError:
            versions[mod] = 'not installed'

    manifest = {
        'droidtrace_version': __version__,
        'started_utc': started.isoformat(),
        'ended_utc': ended.isoformat(),
        'target': args.package,
        'mode': 'host' if args.host else ('attach' if args.attach else 'spawn'),
        'device': None if args.host else args.device,
        'duration_requested_s': args.duration,
        'versions': versions,
        # The path alone does not identify what actually ran: the agent is a build
        # artifact, and a rebuild changes its behaviour without changing its name.
        # Without the digest there is no way to tie a finding to the code that
        # produced it — which for a forensic tool breaks the chain of custody.
        'tracer_script': os.path.abspath(args.script),
        'tracer_script_sha256': file_digest(args.script),
        'tracer_meta': plugin.meta,
        'tracer_errors': plugin.errors,
        'tracer_warnings': plugin.warnings,
        'records': len(plugin.records),
        'session_stopped_cleanly': stop_clean,
        'artifacts': {name: digest(name) for name in run_artifacts(out_dir)},
    }
    path = os.path.join(out_dir, 'run_manifest.json')
    with open(path, 'w') as out:
        json.dump(manifest, out, indent=2)
    print(f'[+] manifest: {path}')


def warn_about_secrets(out_dir):
    print(f'\n[!] {out_dir} holds captured traffic and TLS key material. Treat it as '
          f'sensitive: it can reveal credentials and personal data — including data '
          f'belonging to people who are not the subject of your analysis — and it may '
          f'include material you are not authorised to redistribute.')


def prepare_output(out_dir):
    """Create the directory private, and move this tool's own stale artifacts
    aside so a previous run's pcap can never be summarized as if it were this
    one's.

    Moved, not deleted: rerunning into the same directory is an easy mistake,
    and the captures and keylogs it would destroy are often not reproducible —
    the app has since been uninstalled, the C2 has gone quiet, the phone has
    been returned. Losing evidence must not be the default.
    """
    os.makedirs(out_dir, mode=0o700, exist_ok=True)
    try:
        os.chmod(out_dir, 0o700)
    except OSError:
        pass
    stale = run_artifacts(out_dir)
    if not stale:
        return None
    when = datetime.fromtimestamp(
        os.path.getmtime(os.path.join(out_dir, stale[0])), timezone.utc)
    archive = os.path.join(out_dir, 'previous_run_' + run_stamp(out_dir, when))
    os.makedirs(archive, mode=0o700, exist_ok=True)
    for name in stale:
        os.replace(os.path.join(out_dir, name), os.path.join(archive, name))
    print(f'[!] a previous run was found here; its artifacts were moved to '
          f'{archive}/ ({", ".join(stale)})')
    return archive


# --------------------------------------------------------------------------- main

def parse_args(argv=None):
    ap = argparse.ArgumentParser(
        description='Java call-stack attribution for Android network traffic, '
                    'as a friTap plugin.')
    ap.add_argument('--device', help='adb/Frida device id, e.g. emulator-5554 '
                                     '(required unless --host or --postprocess-only)')
    ap.add_argument('--package', help='target app package name (or a local command with --host)')
    ap.add_argument('--output', required=True, help='output directory')
    ap.add_argument('--script', default=DEFAULT_SCRIPT, help='tracer script path')
    ap.add_argument('--duration', type=int, default=200, help='collection window, seconds')
    ap.add_argument('--attach', action='store_true',
                    help='attach to an already running app instead of spawning it')
    ap.add_argument('--tcpdump', help='path to tcpdump on the device if not in PATH')
    ap.add_argument('--host', action='store_true',
                    help='run against a local process instead of a device — verifies the '
                         'toolchain, e.g. --host --package "/usr/bin/curl -s https://example.com"')
    ap.add_argument('--anti-root', dest='anti_root', action='store_true', default=None,
                    help="turn friTap's root-evasion hooks on (off by default: they "
                         "crash friTap's own script on Android 14)")
    ap.add_argument('--no-anti-root', dest='anti_root', action='store_false',
                    help="force friTap's root-evasion hooks off")
    ap.add_argument('--keep-device-artifacts', action='store_true',
                    help='do not delete the capture file from the device afterwards')
    ap.add_argument('--no-postprocess', action='store_true', help='capture only')
    ap.add_argument('--postprocess-only', action='store_true',
                    help='only decrypt and summarize what is already in --output')
    return ap, ap.parse_args(argv)


def main():
    ap, args = parse_args()

    if args.postprocess_only:
        decrypt_and_summarize(args.output, args.package or args.output)
        return
    if not args.package:
        ap.error('--package is required')
    if not args.host and not args.device:
        ap.error('--device is required (or use --host)')

    preflight(args)
    prepare_output(args.output)

    from friTap.api import FriTap

    jsonl = os.path.join(args.output, 'socket_trace.jsonl')
    plugin = build_plugin(args.script, jsonl)
    keylog = os.path.join(args.output, 'sslkeylog.txt')

    # Installed before anything is started on the device: an interrupt during a
    # slow spawn must still reach the cleanup path.
    interrupts = {'count': 0}

    def handler(signum, frame):
        interrupts['count'] += 1
        if interrupts['count'] > 1:
            print('\n[!] second interrupt — exiting now; artifacts already on disk are kept')
            os._exit(130)
        print('\n[+] interrupt received — finishing up')
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

    def cleanup_device():
        if not args.host:
            stop_capture(args.device, args.output, args.keep_device_artifacts)

    if not args.host:
        if not ensure_frida_server(args.device, args.device):
            sys.exit(1)
        if not start_capture(args.device, args.tcpdump):
            print('[!] continuing without a pcap — keys and call stacks are still collected')

    fritap = FriTap(args.package).keylog(keylog).add_script_plugin(plugin)
    fritap = fritap.spawn(not args.attach)
    if not args.host:
        fritap = fritap.mobile(args.device)
        # friTap's anti-root module throws inside its own script on Android 14 --
        # "cannot read property 'indexOf' of undefined" -- and the session never
        # starts. Reproduced on both spawn and attach, on arm64 and x86_64, so it
        # is off unless asked for: a default that reliably prevents the tool from
        # running is not a useful default. Samples that actually check for root
        # need `--anti-root`, and attaching to a running app never does -- it has
        # already passed its own checks.
        anti_root = False if args.anti_root is None else args.anti_root
        if anti_root:
            fritap = fritap.anti_root(True)
        else:
            print('[i] anti-root evasion off (default -- it crashes friTap on '
                  'Android 14; --anti-root forces it on)')

    started = datetime.now(timezone.utc)
    print(f'[+] starting friTap ({"attach" if args.attach else "spawn"}) on {args.package}')
    try:
        session = fritap.start()
    except BaseException as exc:          # KeyboardInterrupt is not an Exception
        print(f'[!] friTap failed to start: {exc.__class__.__name__}: {exc}')
        if 'ProcessNotFound' in exc.__class__.__name__:
            suggest_process_names(args)
        cleanup_device()
        plugin.close_sink()
        sys.exit(1)

    print(f'[+] collecting for {args.duration}s (Ctrl-C to stop early) — '
          f'drive the app so it actually reaches the network')
    deadline = time.time() + args.duration
    target_gone = False
    while time.time() < deadline and not interrupts['count']:
        time.sleep(2)
        if plugin.last_message is not None and \
                time.monotonic() - plugin.last_message > HEARTBEAT_TIMEOUT:
            target_gone = True
            print(f'\n[+] no tracer heartbeat for {HEARTBEAT_TIMEOUT}s — the target has '
                  f'ended; wrapping up early')
            break
        keys = 0
        if os.path.exists(keylog):
            with open(keylog) as fh:
                keys = sum(1 for _ in fh)
        print(f'\r    TLS keys: {keys}, socket ops: {len(plugin.records)}   ',
              end='', flush=True)
    print()

    # Everything is finalized BEFORE the session is stopped. Stopping can hang on
    # a wedged target, and friTap's own detach path may terminate the process
    # outright — either way the evidence must already be on disk.
    plugin.close_sink()
    with open(os.path.join(args.output, 'socket_trace.json'), 'w') as out:
        json.dump(plugin.records, out, indent=2)
    print(f'[+] socket_trace.json: {len(plugin.records)} records')
    if plugin.counts:
        with open(os.path.join(args.output, 'socket_trace_counts.json'), 'w') as out:
            json.dump(plugin.counts, out, indent=2)
    if plugin.meta or plugin.errors or plugin.warnings:
        with open(os.path.join(args.output, 'socket_trace_meta.json'), 'w') as out:
            json.dump({**(plugin.meta or {}), 'errors': plugin.errors,
                       'warnings': plugin.warnings,
                       'target_ended_early': target_gone}, out, indent=2)
    cleanup_device()

    stopper = threading.Thread(target=_safe_stop, args=(session,), daemon=True)
    stopper.start()
    stopper.join(STOP_TIMEOUT)
    stop_clean = not stopper.is_alive()
    if not stop_clean:
        where = 'locally' if args.host else 'on the device'
        print(f'[!] friTap did not stop within {STOP_TIMEOUT}s — continuing anyway; '
              f'a stray process may be left behind {where}. All artifacts were '
              f'written before the stop was attempted.')

    if not args.no_postprocess:
        decrypt_and_summarize(args.output, args.package,
                              target_is_recorded=True, stamp=started)
    write_manifest(args.output, args, plugin, started, datetime.now(timezone.utc), stop_clean)
    warn_about_secrets(args.output)


def _safe_stop(session):
    try:
        session.stop()
        print('[+] friTap session stopped')
    except Exception as exc:
        print(f'[!] stopping the session: {exc}')


if __name__ == '__main__':
    main()
