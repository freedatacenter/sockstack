#!/usr/bin/env python3
"""
sockstack ui — a local web front-end for the sockstack CLI.

The CLI is the product; this is a window onto it. Every run it starts is an
ordinary `sockstack.py` invocation whose artifacts land in an ordinary output
directory, so anything done here can be redone, scripted or audited without it.

It exists for one reason above the others: driving the target. Reaching the
network usually means touching the app, and from a terminal that is
`input tap 797 1284` — coordinates obtained by dumping the view hierarchy,
parsing XML and computing a centre by hand, which is slow and lands on the wrong
thing often enough to cost a whole run. Here the device's screen is on the page
and the view hierarchy is an overlay, so a tap is a click on the button rather
than a guess at where the button is.

    python3 ui/server.py                 # http://127.0.0.1:8722

Security, stated plainly rather than assumed: this server runs adb commands,
accepts file uploads and installs APKs on the attached device. Anyone who can
reach it can do the same. There is no authentication. It binds to loopback only unless told otherwise, and
the right way to use it from another machine is an SSH tunnel:

    ssh -L 8722:127.0.0.1:8722 user@analysis-host

`--bind` exists for the cases where that is impractical, and says what it costs.
"""
import argparse
import errno
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
# The page renders peers and call sites, and it must reach the same conclusions
# as the written report. The only way to guarantee that is to use the same code:
# no second implementation to drift, no second definition of "attributed".
import sockstack                                                      # noqa: E402
SOCKSTACK = os.path.join(ROOT, 'sockstack.py')
SETUP_DEVICE = os.path.join(ROOT, 'setup-device.sh')
# Enough history that a long run stays readable, bounded so a chatty target
# cannot exhaust memory on the analysis host.
LOG_LINES = 4000
# The browser is often not on the machine holding the APK — the usual shape is a
# laptop tunnelled into the stand. A path field alone only works for files that
# are already on the analysis host, so uploads land here and are installed from
# here. Kept out of the output directory: this is transport, not evidence.
UPLOAD_DIR = os.path.join(tempfile.gettempdir(), 'sockstack-ui-uploads')
MAX_UPLOAD = 1024 * 1024 * 1024


def safe_upload_name(raw):
    """A filename from the browser is attacker-adjacent input; keep the basename
    and nothing that could climb out of UPLOAD_DIR."""
    name = os.path.basename((raw or '').strip().replace('\\', '/'))
    name = re.sub(r'[^A-Za-z0-9._-]', '_', name).lstrip('.')
    return name[:120] or 'upload.apk'


# --------------------------------------------------------------------------- adb plumbing

def adb(serial, *args, timeout=60, binary=False):
    """Run an adb command. Returns (ok, output)."""
    cmd = ['adb'] + (['-s', serial] if serial else []) + list(args)
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except FileNotFoundError:
        return False, b'' if binary else 'adb not found in PATH'
    except subprocess.TimeoutExpired:
        return False, b'' if binary else f'adb timed out after {timeout}s'
    if binary:
        return result.returncode == 0, result.stdout
    text = (result.stdout or b'').decode('utf-8', 'replace')
    err = (result.stderr or b'').decode('utf-8', 'replace')
    return result.returncode == 0, text if result.returncode == 0 else (err or text)


# --------------------------------------------------------------------------- parsing (pure)

def connect_verdict(ok, out):
    """Did `adb connect` connect?

    It exits 0 whether or not it did — "failed to connect to 10.0.0.5:5555" is a
    successful run of a command that failed at its job. The exit status is
    therefore not the answer; the sentence is. Reporting the exit status would
    put a device in the list that is not there.
    """
    text = (out or '').strip()
    good = text.lower().startswith(('connected to', 'already connected to'))
    return {'ok': bool(ok) and good, 'output': text or 'adb said nothing at all'}


def pair_verdict(ok, out):
    """Same shape for `adb pair`, which also reports failure through its words."""
    text = (out or '').strip()
    return {'ok': bool(ok) and 'successfully paired' in text.lower(),
            'output': text or 'adb said nothing at all'}


def adb_server_label():
    """Which adb server these commands talk to.

    Worth stating on the page: the recipe for a device on another machine is to
    forward that machine's adb server and point the client at the near end, and
    nothing else here would show whether it took effect.
    """
    return (os.environ.get('ADB_SERVER_SOCKET')
            or f"tcp:127.0.0.1:{os.environ.get('ANDROID_ADB_SERVER_PORT') or 5037}")


def is_network_device(serial):
    """host:port, as `adb connect` produces. USB serials have no colon, and a
    port that is not a number is a serial that happens to contain one."""
    host, _, port = (serial or '').rpartition(':')
    return bool(host) and port.isdigit()


def device_hint(state, network):
    """Translation key for "why is this device not usable, and what fixes it".

    One message for every unusable state is worse than none, because the states
    have different cures and the wrong cure sends the reader off for minutes.
    `unauthorized` really does mean a prompt is waiting on the screen. `offline`
    on a network device almost never does — it means the path to it died, and
    the ssh tunnel is the first thing to look at. Telling that operator to
    accept a prompt points them at a device they cannot even reach.
    """
    if state == 'device':
        return ''
    if state == 'unauthorized':
        return 'dev.hint.unauth'
    if state == 'offline':
        return 'dev.hint.offline.net' if network else 'dev.hint.offline.usb'
    return 'dev.hint.other'


def parse_devices(text):
    """`adb devices -l` -> [{serial, state, model, network, hint}].

    Devices that are present but not usable — unauthorized, offline — are kept
    and labelled rather than filtered out: "no devices" when one is plugged in
    and unauthorized sends the reader looking for a cable problem.
    """
    devices = []
    for line in (text or '').splitlines():
        line = line.strip()
        if not line or line.startswith('List of devices'):
            continue
        fields = line.split()
        if len(fields) < 2:
            continue
        model = ''
        for field in fields[2:]:
            if field.startswith('model:'):
                model = field[len('model:'):].replace('_', ' ')
        network = is_network_device(fields[0])
        devices.append({'serial': fields[0], 'state': fields[1], 'model': model,
                        'network': network,
                        'hint': device_hint(fields[1], network)})
    return devices


def parse_packages(listing, times=None):
    """`pm list packages -3 -U` (+ optional install times) -> sorted newest first.

    Newest first because the package you want is almost always the one you just
    installed, and its name rarely resembles the file it came from.
    """
    packages = []
    for line in (listing or '').splitlines():
        fields = line.strip().split()
        if not fields or not fields[0].startswith('package:'):
            continue
        name = fields[0][len('package:'):]
        uid = None
        for field in fields[1:]:
            if field.startswith('uid:') and field[4:].isdigit():
                uid = int(field[4:])
        packages.append({'package': name, 'uid': uid,
                         'installed': (times or {}).get(name, '')})
    packages.sort(key=lambda p: (p['installed'] or '', p['package']), reverse=True)
    return packages


BOUNDS_RE = re.compile(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]')


def parse_ui_elements(xml):
    """uiautomator XML -> clickable elements with their centres.

    Only clickable nodes are kept, and each carries whatever identifies it to a
    human: the resource id, the visible text, the content description. Clicking
    `installUpdateBtn` is a different act from clicking the point 797,1284 — the
    first survives a device with another screen size, the second does not.
    """
    elements = []
    for node in re.finditer(r'<node\b[^>]*/?>', xml or ''):
        tag = node.group(0)
        if 'clickable="true"' not in tag:
            continue
        bounds = BOUNDS_RE.search(tag)
        if not bounds:
            continue
        x1, y1, x2, y2 = (int(v) for v in bounds.groups())
        if x2 <= x1 or y2 <= y1:
            continue

        def attr(name):
            found = re.search(rf'{name}="([^"]*)"', tag)
            return found.group(1) if found else ''

        resource = attr('resource-id').rsplit('/', 1)[-1]
        elements.append({
            'id': resource,
            'text': attr('text'),
            'desc': attr('content-desc'),
            'cls': attr('class').rsplit('.', 1)[-1],
            'bounds': [x1, y1, x2, y2],
            'center': [(x1 + x2) // 2, (y1 + y2) // 2],
        })
    return elements


def parse_install_times(dumps):
    """{package: 'YYYY-MM-DD HH:MM:SS'} from concatenated `dumpsys package` output."""
    times, current = {}, None
    for line in (dumps or '').splitlines():
        line = line.strip()
        if line.startswith('== '):
            current = line[3:].strip()
        elif current and line.startswith('firstInstallTime='):
            times[current] = line.split('=', 1)[1].strip()
    return times


# --------------------------------------------------------------------------- findings

# What colour a peer earns, and why. Ranked from "the tool knows which code did
# this" down to "the tool did not look" — the same ordering the report uses, for
# the same reason: an unexamined destination must never look more settled than an
# examined one. Nothing here encodes suspicion. The tool cannot tell a C2 from a
# CDN, and a red badge that says otherwise would be exactly the confident wrong
# answer this project spends its effort avoiding.
PEER_KINDS = {
    'app': ('names application code', 'good'),
    'library': ('a stack, but only library frames', 'partial'),
    'framework-only': ('a stack, but only framework frames', 'partial'),
    'native-thread': ('no JVM on the calling thread', 'partial'),
    'no-runtime': ('the process has no Java runtime', 'partial'),
    'not-examined': ('never stack-walked — more callers may exist', 'unknown'),
    'attribution-unavailable': ('the Java bridge was not working here', 'unknown'),
    'unknown': ('no reason recorded — treat as unexamined', 'unknown'),
    'kernel-only': ('the kernel saw it; the tracer has no record', 'unknown'),
    # Worth its own label rather than folding into kernel-only: this address was
    # too short-lived for a 2-second sample to catch, and saying so is the whole
    # argument for reading kernel events instead of polling kernel state.
    'event-stream-only': ('only the kernel event stream saw it — the tracer has '
                          'no record and the 2-second poll missed it', 'unknown'),
}


def attribution_cards(out_dir):
    """Peers with their call sites, classified for display.

    Built from sockstack's own summary functions so the page cannot claim
    something the report would not.
    """
    if not out_dir or not os.path.isdir(out_dir):
        return {'ok': False, 'error': 'no such directory', 'cards': []}
    records = sockstack._load_records(out_dir)
    counts = sockstack._load_json(
        os.path.join(out_dir, 'socket_trace_counts.json'), {}).get('counts')
    peers, attribution, unattributed, partly = sockstack.summarize_trace(records, counts)
    meta = sockstack._load_json(os.path.join(out_dir, 'socket_trace_meta.json'), {})
    uid_blob = sockstack._load_json(os.path.join(out_dir, 'uid_sockets.json'), {})

    grouped = {}
    for item in attribution:
        entry = grouped.setdefault(item['peer'], [])
        entry.append({'app': item['app_frames'], 'via': item['via']})
    cards = []
    for peer, sites in sorted(grouped.items()):
        kind = 'app' if any(s['app'] for s in sites) else 'library'
        cards.append({'peer': peer, 'kind': kind, 'sites': sites,
                      'note': 'attributed, but not exhaustively — the stack-walk '
                              'budget ran out' if peer in partly else ''})
    for reason, addresses in (unattributed or {}).items():
        for peer in addresses:
            cards.append({'peer': peer, 'kind': reason, 'sites': [], 'note': ''})

    seen = {card['peer'] for card in cards}
    for entry in uid_blob.get('peers', []):
        peer = sockstack.format_peer(entry.get('ip'), entry.get('port'))
        if peer not in seen and entry.get('ip'):
            sources = entry.get('sources') or []
            cards.append({'peer': peer, 'sites': [],
                          'kind': ('event-stream-only' if sources == ['ftrace']
                                   else 'kernel-only'),
                          'sources': sources,
                          'note': '' if entry.get('established', True)
                                  else 'attempted, never established'})

    for card in cards:
        label, tone = PEER_KINDS.get(card['kind'], PEER_KINDS['unknown'])
        card['label'], card['tone'] = label, tone
        card['ops'] = sum(v for k, v in peers.items() if k.startswith(card['peer'] + ' '))

    sources = {}
    for rec in records:
        key = rec.get('stack_source') or 'unknown'
        sources[key] = sources.get(key, 0) + 1
    return {'ok': True, 'cards': cards, 'records': len(records), 'sources': sources,
            'bridge': meta.get('java_bridge'), 'runtime': meta.get('android_runtime'),
            'cross_check': {k: v for k, v in uid_blob.items() if k != 'peers'}}


# A body can be a megabyte of protobuf. The page needs enough to recognise what
# was sent, not the whole payload — the file on disk is the artifact, and the
# panel says when it is showing less than there is.
BODY_CHARS = 4000
MAX_BODIES = 40


PRINTABLE = set(range(0x20, 0x7f)) | {0x09, 0x0a, 0x0d}
STRING_RUN = re.compile(rb'[\x20-\x7e]{4,}')
HEX_BYTES = 1024


def render_body(raw):
    """One body, shown the way its contents deserve.

    Decoding protobuf as UTF-8 produces a screen of replacement characters with
    the useful parts — versions, package names, identifiers — buried in them. So
    a body that is mostly unprintable is offered as its printable runs, the way
    `strings` would, with the bytes themselves a click away. Text is still text.
    """
    printable = sum(1 for byte in raw if byte in PRINTABLE)
    binary = bool(raw) and printable / len(raw) < 0.85
    body = {'bytes': len(raw), 'binary': binary, 'hex': '', 'text': ''}
    if not binary:
        body['text'] = raw.decode('utf-8', 'replace')[:BODY_CHARS]
        body['clipped'] = len(raw) > BODY_CHARS
        return body
    runs = [run.decode('ascii') for run in STRING_RUN.findall(raw)]
    body['text'] = '\n'.join(runs)[:BODY_CHARS]
    body['strings'] = len(runs)
    window = raw[:HEX_BYTES]
    lines = []
    for offset in range(0, len(window), 16):
        chunk = window[offset:offset + 16]
        gutter = ''.join(chr(b) if b in PRINTABLE and b >= 0x20 else '.' for b in chunk)
        lines.append(f'{offset:08x}  {chunk.hex(" "):<47}  {gutter}')
    body['hex'] = '\n'.join(lines)
    body['clipped'] = len(raw) > HEX_BYTES
    return body


def peer_address(peer):
    """`1.2.3.4:443` / `[::1]:443` -> the address alone."""
    text = (peer or '').strip()
    if text.startswith('['):
        return text[1:].split(']', 1)[0]
    return text.rsplit(':', 1)[0] if ':' in text else text


def stream_state(pcap, enc, ip, saw_http):
    """Was this peer's traffic readable, or merely present?

    Three outcomes that must not be allowed to look alike: read it, saw it and
    could not read it, never saw it. An app that speaks its own protocol over a
    raw socket produces TLS records friTap has no keys for — and rendering that
    as an empty request list would say "it sent nothing", which is the opposite
    of what happened.
    """
    if saw_http:
        return 'decrypted'
    if not ip:
        return ''
    family = 'ipv6.addr' if ':' in ip else 'ip.addr'
    for path in (enc, pcap):
        if not path or not os.path.exists(path):
            continue
        rows, err = sockstack.tshark_fields(path, f'{family} == {ip} && tls.app_data',
                                            'frame.number')
        if err:
            return ''
        if rows:
            return 'encrypted'
    return 'absent'


def traffic_view(out_dir, peer=''):
    """Requests and decrypted bodies from a finished run, optionally for one peer.

    Both come from sockstack's own extraction, so the panel and the written
    report cannot disagree about what was sent.

    Filtering is by **destination**, and the caller has to say so. The tracer
    records no payload — a record carries the fd, the thread, the address and the
    stack — so a body can be tied to the address a call site contacted and no
    further. Where two call sites share a destination, which of them sent a given
    body is not something this data can answer, and the page must not imply it.
    """
    if not out_dir or not os.path.isdir(out_dir):
        return {'ok': False, 'error': 'no such directory', 'requests': [],
                'bodies': []}
    pcap = os.path.join(out_dir, 'traffic.pcap')
    enc = os.path.join(out_dir, 'decrypted.pcapng')
    if not os.path.exists(pcap) and not os.path.exists(enc):
        return {'ok': False, 'error': 'no capture in this directory — a run with '
                                      '--host, or one that never got a pcap',
                'requests': [], 'bodies': []}
    if not shutil.which('tshark'):
        return {'ok': False, 'error': 'tshark is not installed, so nothing can be '
                                      'read out of the capture',
                'requests': [], 'bodies': []}

    records = sockstack._load_records(out_dir)
    counts = sockstack._load_json(
        os.path.join(out_dir, 'socket_trace_counts.json'), {}).get('counts')
    target_ips = sockstack.tracer_ips(records, counts)
    uid_blob = sockstack._load_json(os.path.join(out_dir, 'uid_sockets.json'), {})
    target_ips |= {e['ip'] for e in uid_blob.get('peers', []) if e.get('ip')}

    wanted = peer_address(peer)
    http1, http2 = sockstack.http_exchanges(pcap, enc, target_ips)
    requests = []
    for proto, table in (('HTTP/1', http1), ('HTTP/2', http2)):
        for label, entry in sorted(table.items()):
            if wanted and wanted not in entry['ips']:
                continue
            requests.append({'label': label, 'target': entry['target'],
                             'proto': proto, 'ips': entry['ips']})

    placed, fragmented = sockstack.collect_bodies(pcap, enc)
    if wanted:
        placed = [(ip, text) for ip, text in placed if ip == wanted]
    truncated = len(placed) > MAX_BODIES
    bodies = []
    for address, raw in placed[:MAX_BODIES]:
        body = render_body(raw)
        truncated = truncated or body.pop('clipped', False)
        bodies.append(dict(body, ip=address))
    return {'ok': True, 'error': '', 'peer': peer, 'requests': requests,
            'bodies': bodies, 'truncated': truncated, 'fragmented': fragmented,
            'state': stream_state(pcap, enc, wanted, bool(requests or bodies)),
            # Not decoration: an unmarked request is one nobody tied to the
            # target, and the capture is device-wide.
            'attributed': sum(1 for r in requests if r['target'])}


def recent_runs(root):
    """Runs found under `root`, newest first, described by what they recorded.

    Deliberately no verdict. "Clean" is not something a run can report: nothing
    found and nothing working look the same from here, and only the manifest can
    say which it was.
    """
    runs = []
    if not root or not os.path.isdir(root):
        return runs
    for name in os.listdir(root):
        directory = os.path.join(root, name)
        manifest = os.path.join(directory, 'run_manifest.json')
        if not os.path.isfile(manifest):
            continue
        blob = sockstack._load_json(manifest, {})
        summary = attribution_cards(directory)
        runs.append({
            'dir': directory, 'name': name,
            'target': blob.get('target', name), 'mode': blob.get('mode', ''),
            'started': (blob.get('started_utc') or '')[:16].replace('T', ' '),
            'records': blob.get('records', summary.get('records', 0)),
            'sites': sum(len(c['sites']) for c in summary.get('cards', [])),
            'bridge': summary.get('bridge'),
        })
    runs.sort(key=lambda r: r['started'], reverse=True)
    return runs[:12]


# --------------------------------------------------------------------------- the run

class Run:
    """One sockstack invocation, with its output kept for the page to poll.

    Deliberately at most one at a time: two runs share a device, a frida-server
    and a tcpdump, and letting the UI start a second would corrupt both in ways
    the artifacts would not explain.
    """

    def __init__(self):
        self.process = None
        self.lines = deque(maxlen=LOG_LINES)
        self.first_index = 0
        self.command = []
        self.output_dir = ''
        self.started = 0.0
        self.lock = threading.Lock()

    @property
    def running(self):
        return self.process is not None and self.process.poll() is None

    def start(self, command, output_dir, label):
        if self.running:
            return False, 'a run is already in progress'
        with self.lock:
            self.lines.clear()
            self.first_index = 0
            self.command = command
            self.output_dir = output_dir
            self.started = time.time()
        self._append(f'$ {label}')
        self.process = subprocess.Popen(
            command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, errors='replace')
        threading.Thread(target=self._drain, daemon=True).start()
        return True, 'started'

    def _append(self, line):
        with self.lock:
            if len(self.lines) == self.lines.maxlen:
                self.first_index += 1
            self.lines.append(line)

    def _drain(self):
        for line in self.process.stdout:
            # The CLI redraws its progress counter with \r; keep only the last
            # state of it so the log does not fill with partial repeats.
            self._append(line.rstrip('\n').split('\r')[-1])
        code = self.process.wait()
        self._append(f'— finished, exit status {code} —')

    def stop(self):
        """Ask for an early finish rather than killing: the CLI treats SIGINT as
        'wrap up now', and everything collected so far is still written out."""
        if not self.running:
            return False, 'nothing is running'
        self.process.send_signal(signal.SIGINT)
        return True, 'asked the run to finish early'

    def tail(self, since):
        with self.lock:
            start = max(0, since - self.first_index)
            return {'lines': list(self.lines)[start:],
                    'next': self.first_index + len(self.lines),
                    'running': self.running,
                    'output': self.output_dir,
                    'elapsed': int(time.time() - self.started) if self.started else 0}


RUN = Run()


# --------------------------------------------------------------------------- http

class Handler(BaseHTTPRequestHandler):
    server_version = 'sockstack-ui'

    def log_message(self, *args):
        pass        # the run log is the interesting output, not access lines

    # -- helpers -----------------------------------------------------------
    def _send(self, code, body, content_type='application/json'):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        try:
            self.send_response(code)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            # The page polls; a reload or a closed tab aborts requests in flight
            # and there is nobody left to answer. Normal, and nothing the reader
            # can act on — but printed as a traceback it reads as a crash, and
            # worse, it buries the real exception when this send was the 500.
            pass

    def _body(self):
        length = int(self.headers.get('Content-Length') or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length) or b'{}')
        except json.JSONDecodeError:
            return {}

    # -- routing -----------------------------------------------------------
    def do_GET(self):
        url = urlparse(self.path)
        query = {k: v[0] for k, v in parse_qs(url.query).items()}
        serial = query.get('device') or None
        try:
            if url.path in ('/', '/index.html'):
                with open(os.path.join(HERE, 'index.html'), 'rb') as fh:
                    return self._send(200, fh.read(), 'text/html; charset=utf-8')
            if url.path == '/api/devices':
                ok, out = adb(None, 'devices', '-l')
                return self._send(200, {'ok': ok, 'devices': parse_devices(out) if ok else [],
                                        'server': adb_server_label(),
                                        'error': '' if ok else out})
            if url.path == '/api/packages':
                return self._send(200, self._packages(serial))
            if url.path == '/api/screen':
                png, why = self._screencap(serial)
                if not png:
                    return self._send(503, {'error': why or 'screencap failed'})
                return self._send(200, png, 'image/png')
            if url.path == '/api/elements':
                return self._send(200, self._elements(serial))
            if url.path == '/api/log':
                return self._send(200, RUN.tail(int(query.get('since') or 0)))
            if url.path == '/api/deviceinfo':
                return self._send(200, self._device_info(serial))
            if url.path == '/api/traffic':
                return self._send(200, traffic_view(query.get('dir') or '',
                                                    query.get('peer') or ''))
            if url.path == '/api/attribution':
                return self._send(200, attribution_cards(query.get('dir') or ''))
            if url.path == '/api/runs':
                return self._send(200, {'runs': recent_runs(
                    query.get('root') or os.getcwd())})
            if url.path == '/api/report':
                return self._send(200, self._report(query.get('dir') or ''))
            return self._send(404, {'error': 'no such endpoint'})
        except Exception as exc:                            # noqa: BLE001
            # Say it here as well as in the response: if the client is the one
            # that went away, the 500 goes nowhere and the error would vanish
            # with it. This line is the only copy that survives that case.
            print(f'[!] {self.path}: {type(exc).__name__}: {exc}', file=sys.stderr)
            return self._send(500, {'error': f'{type(exc).__name__}: {exc}'})

    def do_POST(self):
        url = urlparse(self.path)
        try:
            # Routed before _body(): the payload is an APK, not JSON, and reading
            # a few hundred megabytes into a string to fail json.loads on it would
            # be a poor way to find that out.
            if url.path == '/api/upload':
                return self._upload()
            data = self._body()
            serial = data.get('device') or None
            if url.path == '/api/tap':
                ok, out = adb(serial, 'shell', 'input', 'tap',
                              str(int(data['x'])), str(int(data['y'])))
                return self._send(200, {'ok': ok, 'output': out})
            if url.path == '/api/swipe':
                ok, out = adb(serial, 'shell', 'input', 'swipe',
                              str(int(data['x1'])), str(int(data['y1'])),
                              str(int(data['x2'])), str(int(data['y2'])),
                              str(int(data.get('ms', 300))))
                return self._send(200, {'ok': ok, 'output': out})
            if url.path == '/api/key':
                ok, out = adb(serial, 'shell', 'input', 'keyevent', str(data['key']))
                return self._send(200, {'ok': ok, 'output': out})
            if url.path == '/api/launch':
                ok, out = adb(serial, 'shell', 'monkey', '-p', str(data['package']),
                              '-c', 'android.intent.category.LAUNCHER', '1')
                return self._send(200, {'ok': ok, 'output': out})
            if url.path == '/api/install':
                return self._send(200, self._install(serial, data.get('path', '')))
            if url.path == '/api/connect':
                address = (data.get('address') or '').strip()
                if not address:
                    return self._send(200, {'ok': False, 'output': 'give an address'})
                # A bare host means the classic debug port; typing it every time
                # is a tax on the common case.
                if ':' not in address:
                    address += ':5555'
                ok, out = adb(None, 'connect', address, timeout=30)
                return self._send(200, dict(connect_verdict(ok, out), address=address))
            if url.path == '/api/disconnect':
                ok, out = adb(None, 'disconnect', (data.get('address') or '').strip())
                return self._send(200, {'ok': ok, 'output': (out or '').strip()})
            if url.path == '/api/pair':
                ok, out = adb(None, 'pair', (data.get('address') or '').strip(),
                              (data.get('code') or '').strip(), timeout=60)
                return self._send(200, pair_verdict(ok, out))
            if url.path == '/api/setup':
                return self._send(200, self._setup(serial, data.get('frida', '')))
            if url.path == '/api/run':
                return self._send(200, self._run(data))
            if url.path == '/api/stop':
                ok, message = RUN.stop()
                return self._send(200, {'ok': ok, 'message': message})
            return self._send(404, {'error': 'no such endpoint'})
        except Exception as exc:                            # noqa: BLE001
            # Say it here as well as in the response: if the client is the one
            # that went away, the 500 goes nowhere and the error would vanish
            # with it. This line is the only copy that survives that case.
            print(f'[!] {self.path}: {type(exc).__name__}: {exc}', file=sys.stderr)
            return self._send(500, {'error': f'{type(exc).__name__}: {exc}'})

    # -- endpoint bodies ---------------------------------------------------
    def _screencap(self, serial):
        """(png, error). Empty PNG with the reason, never a bare failure.

        `adb exec-out` is the fast path and usually correct, but this codebase
        already documents it mixing the remote process's stderr into the binary
        stream (see docs/GOTCHAS.md, where it corrupted pcaps). A header check
        alone would not notice junk in the middle, so the whole frame is checked
        for its terminating IEND chunk, and anything that fails falls back to
        writing on the device and pulling the file — the same fix the pcap path
        uses, at the cost of a round trip.
        """
        ok, png = adb(serial, 'exec-out', 'screencap', '-p', binary=True)
        if ok and png.startswith(b'\x89PNG\r\n\x1a\n') and png.rstrip().endswith(b'IEND\xaeB`\x82'):
            return png, ''
        remote = '/sdcard/sockstack_ui_screen.png'
        ok, why = adb(serial, 'shell', f'screencap -p {remote}')
        if not ok:
            return b'', (why or 'screencap failed on the device').strip()[:200]
        ok, png = adb(serial, 'exec-out', 'cat', remote, binary=True)
        adb(serial, 'shell', f'rm -f {remote}')
        if ok and png.startswith(b'\x89PNG'):
            return png, ''
        return b'', 'the device produced no readable PNG'

    def _device_info(self, serial):
        ok, props = adb(serial, 'shell',
                        'getprop ro.build.version.release ; '
                        'getprop ro.product.cpu.abi ; '
                        'getprop ro.build.type ; '
                        'pidof frida-server')
        lines = [line.strip() for line in (props or '').splitlines()]
        while len(lines) < 4:
            lines.append('')
        return {'ok': ok, 'release': lines[0], 'abi': lines[1],
                'build': lines[2], 'frida': bool(lines[3])}

    def _packages(self, serial):
        ok, listing = adb(serial, 'shell', 'pm list packages -3 -U')
        if not ok:
            return {'ok': False, 'error': listing, 'packages': []}
        names = [line.split()[0][len('package:'):]
                 for line in listing.splitlines()
                 if line.strip().startswith('package:')]
        script = ' ; '.join(
            f'echo "== {n}" ; dumpsys package {n} | grep -m1 firstInstallTime'
            for n in names[:60])
        times = {}
        if script:
            got, dumps = adb(serial, 'shell', script, timeout=90)
            if got:
                times = parse_install_times(dumps)
        return {'ok': True, 'packages': parse_packages(listing, times)}

    def _elements(self, serial):
        ok, out = adb(serial, 'shell',
                      'uiautomator dump /sdcard/sockstack_ui.xml >/dev/null 2>&1 ; '
                      'cat /sdcard/sockstack_ui.xml ; rm -f /sdcard/sockstack_ui.xml',
                      timeout=45)
        if not ok or '<node' not in out:
            # A screen mid-animation has no stable hierarchy to dump. That is
            # normal and temporary; saying so beats an empty overlay.
            return {'ok': False, 'elements': [],
                    'error': 'no view hierarchy right now (screen busy?)'}
        return {'ok': True, 'elements': parse_ui_elements(out)}

    def _package_names(self, serial):
        """Names only — the install-time lookup costs one adb call per package
        and is not worth paying twice around an install."""
        ok, listing = adb(serial, 'shell', 'pm list packages -3')
        return {line.strip()[len('package:'):] for line in (listing or '').splitlines()
                if line.strip().startswith('package:')} if ok else set()

    def _upload(self):
        length = int(self.headers.get('Content-Length') or 0)
        if length <= 0:
            return self._send(400, {'ok': False, 'error': 'empty upload'})
        if length > MAX_UPLOAD:
            return self._send(413, {'ok': False, 'error': 'file larger than 1 GiB'})
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        path = os.path.join(UPLOAD_DIR, safe_upload_name(self.headers.get('X-Filename')))
        remaining = length
        with open(path, 'wb') as fh:
            while remaining > 0:
                chunk = self.rfile.read(min(1 << 20, remaining))
                if not chunk:
                    break
                fh.write(chunk)
                remaining -= len(chunk)
        if remaining > 0:
            # A truncated APK does install-and-fail with a parse error that reads
            # like a broken sample rather than a broken transfer. Say which it is.
            os.remove(path)
            return self._send(400, {'ok': False,
                                    'error': f'upload ended {remaining} bytes early'})
        return self._send(200, {'ok': True, 'path': path, 'bytes': length})

    def _install(self, serial, path):
        if not path or not os.path.isfile(path):
            return {'ok': False, 'output': f'no such file: {path}'}
        before = self._package_names(serial)
        ok, out = adb(serial, 'install', '-r', path, timeout=300)
        after = self._packages(serial).get('packages', [])
        fresh = [p for p in after if p['package'] not in before]
        return {'ok': ok, 'output': out.strip(),
                # The whole point of doing the install here: the name the tracer
                # needs is the one thing the APK's filename will not tell you.
                'installed': fresh[0]['package'] if len(fresh) == 1 else '',
                'packages': after}

    def _setup(self, serial, frida):
        if not os.path.isfile(SETUP_DEVICE):
            return {'ok': False, 'output': 'setup-device.sh is missing'}
        command = ['bash', SETUP_DEVICE, serial] + ([frida] if frida else [])
        ok, message = RUN.start(command, '', ' '.join(command))
        return {'ok': ok, 'message': 'provisioning; watch the log' if ok else message}

    def _run(self, data):
        output = (data.get('output') or '').strip()
        if not output:
            return {'ok': False, 'message': 'choose an output directory'}
        command = [sys.executable, SOCKSTACK, '--output', output]
        if data.get('host'):
            command.append('--host')
        else:
            command += ['--device', data.get('device') or '']
        if data.get('package'):
            command += ['--package', data['package']]
        if data.get('duration'):
            command += ['--duration', str(int(data['duration']))]
        if data.get('attach'):
            command.append('--attach')
        if data.get('anti_root'):
            command.append('--anti-root')
        if data.get('ftrace'):
            command.append('--ftrace')
        if data.get('postprocess_only'):
            command.append('--postprocess-only')
        ok, message = RUN.start(command, output, ' '.join(command))
        return {'ok': ok, 'message': message}

    def _report(self, directory):
        if not directory or not os.path.isdir(directory):
            return {'ok': False, 'error': 'no such directory', 'reports': []}
        reports = sorted(n for n in os.listdir(directory)
                         if n.startswith('summary_') and n.endswith('.md'))
        if not reports:
            return {'ok': False, 'error': 'no summary in this directory',
                    'reports': [], 'artifacts': sorted(os.listdir(directory))}
        with open(os.path.join(directory, reports[-1]), encoding='utf-8',
                  errors='replace') as fh:
            body = fh.read()
        return {'ok': True, 'name': reports[-1], 'body': body,
                'reports': reports, 'artifacts': sorted(os.listdir(directory))}


def main():
    ap = argparse.ArgumentParser(
        description='Local web front-end for sockstack: pick a device, install a '
                    'target, drive it by clicking its actual buttons, watch the run.')
    ap.add_argument('--port', type=int, default=8722)
    ap.add_argument('--bind', default='127.0.0.1',
                    help='interface to listen on (default loopback; anything else '
                         'exposes device control to that network — see below)')
    args = ap.parse_args()
    # Block buffering would hold these until the process exits — which for a
    # server means never. One of them warns that the device is exposed.
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except AttributeError:                              # pragma: no cover
        pass

    if not shutil.which('adb'):
        print('[!] adb is not in PATH — device features will not work')
    if not os.path.exists(SOCKSTACK):
        sys.exit(f'[!] {SOCKSTACK} not found: run this from a sockstack checkout')
    if args.bind not in ('127.0.0.1', 'localhost', '::1'):
        print(f'[!] listening on {args.bind}, not loopback. This server installs '
              f'APKs and runs adb commands with no authentication: anyone who can '
              f'reach it controls the device. Prefer an SSH tunnel:\n'
              f'    ssh -L {args.port}:127.0.0.1:{args.port} <user>@<this host>')

    try:
        server = ThreadingHTTPServer((args.bind, args.port), Handler)
    except OSError as exc:
        # Starting it twice is the ordinary mistake — over a tunnel, one already
        # runs on the far end. A traceback for that reads like a broken tool.
        if exc.errno == errno.EADDRINUSE:
            sys.exit(f'[!] port {args.port} is already in use. A panel is probably '
                     f'running here already — open http://127.0.0.1:{args.port}, or '
                     f'start this one with --port on a free number.')
        sys.exit(f'[!] could not listen on {args.bind}:{args.port}: {exc.strerror}')
    print(f'[+] sockstack ui on http://{args.bind}:{args.port}')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\n[+] stopped')


if __name__ == '__main__':
    main()
