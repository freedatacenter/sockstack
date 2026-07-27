# sockstack

**Which code path sent this?**

A command-line tool for dynamic analysis of Android network traffic. It records,
for every socket operation, the Java call stack that produced it — so a decrypted
request can be traced back to the class and method that sent it. It is written
for mobile malware analysis and DFIR work against a live device.

It is built on [friTap](https://github.com/fkie-cad/friTap), which already answers
*what* an app sends: friTap hooks the TLS libraries, writes an NSS keylog and
defeats certificate pinning without installing a CA. What it does not say is
*which part of the app* did it. sockstack adds that, through friTap's plugin API
rather than by forking it — and you never have to drive friTap yourself. Run
sockstack; it starts friTap, the capture on the device and the decryption
afterwards.

```
## Call-stack attribution
                          ↓ real output: an Android RAT beaconing to its C2
- `203.0.113.47:9999` ← `k7v2p9x4m1qz.la0.c(Unknown Source:68)`,
                        `k7v2p9x4m1qz.ja0.j(Unknown Source:134)`
- `203.0.113.47:9999` ← `k7v2p9x4m1qz.ik1.j(Unknown Source:70)`,
                        `k7v2p9x4m1qz.ik1.e(Unknown Source:12)`
- `203.0.113.47:9999` ← `k7v2p9x4m1qz.ca0.j(Unknown Source:96)`,
                        `k7v2p9x4m1qz.ca0.e(Unknown Source:12)`,
                        `k7v2p9x4m1qz.wf1.H(Unknown Source:7)`,
                        `k7v2p9x4m1qz.ka0.e(Unknown Source:12)`
  …and four more, all reaching the same C2
```
Seven distinct code paths in one obfuscated package, all beaconing to the same
address — that is the question this tool answers. Note the third entry: it is
printed four frames deep because another path shares its first three, and
collapsing the two would have hidden a real one.

The examples throughout this repository are genuine tool output. The addresses,
hostnames, package and class names in them have been replaced with synthetic
ones — the shape is real, the indicators are not, and nothing here points at
live infrastructure.

That mapping is the point of the project. Everything else here is the plumbing
needed to get a decrypted capture out the other end.

## Division of labour

| | |
|---|---|
| **friTap** | TLS keylog, pinning bypass, root evasion, spawn/attach, device handling |
| **sockstack** | the socket-tracer plugin, packet capture, decryption, summary |

sockstack does not reimplement any part of friTap and does not vendor it — it is
a dependency, used through its public plugin API.

## What you get per run

| File | Contents |
|------|----------|
| `socket_trace.json` | socket operations, each with its **Java call stack** |
| `socket_trace.jsonl` | the same records, written as they arrive — survives a run that is cut short |
| `socket_trace_counts.json` | total operations per peer, including those collapsed by de-duplication |
| `socket_trace_meta.json` | which libc functions were hooked, which were absent, tracer errors |
| `uid_sockets.json` | the kernel's own list of sockets owned by the target, and whether that check could run at all |
| `sslkeylog.txt` | TLS secrets, NSS keylog format |
| `traffic.pcap` | raw capture from the device |
| `decrypted.pcapng` | the capture with secrets injected — opens decrypted in Wireshark |
| `summary_<timestamp>.md` | run status, peers, call-stack attribution, DNS, SNI, HTTP, body previews |
| `decrypted_bodies_<timestamp>.txt` | full decrypted message bodies |
| `run_manifest.json` | timestamps, target, tool and library versions, artifact hashes |

Two behaviours worth knowing, because they exist for a reason:

- **Artifacts are finalized before the friTap session is stopped.** Targets that
  exit early are normal, and stopping a session on a dead target can hang. Nothing
  collected is lost to either.
- **Cleartext is read from the raw capture**, so DNS, SNI and plain HTTP still
  appear when no TLS keys were captured at all. A keyless run degrades; it does not
  go blank.

## Requirements

- A **rooted** Android device: an emulator (`adb root`) or a phone with Magisk.
- **Frida 17.x** on the host and a matching `frida-server` on the device.
- `adb` in PATH, and `tshark`/`editcap` for the decryption step.
- Node is needed only to *rebuild* the agent; the built bundle ships in the tree.

```bash
pip install -r requirements.txt          # friTap 2.x + frida 17.x
# Debian/Ubuntu: apt install tshark android-tools-adb
# macOS:         brew install wireshark android-platform-tools
```

## Quick start

The commands, in order. For the same sequence with real output at every step —
what a healthy run prints, which alarming-looking lines are normal, and how to
read the report section by section — see [**docs/USAGE.md**](docs/USAGE.md).

```bash
# 0. Check the toolchain without a device at all — runs against a local process
python3 sockstack.py --host --package "/usr/bin/curl -s https://example.com" \
    --output ./selftest --duration 30

# 1. Provision the device (frida-server 17.x, and tcpdump if it is a stock phone)
#    The architecture in the filename is Frida's, not Android's: a device
#    reporting arm64-v8a needs …-android-arm64. The script prints the ABI,
#    starts what it pushed, and fails here — not mid-run — if it will not run.
./setup-device.sh emulator-5554 ./frida-server-17.2.0-android-arm64
adb -s emulator-5554 reboot        # the perfetto workaround is a persist prop

#    You do not have to start frida-server yourself: sockstack launches it,
#    and restarts it if a previous session left it wedged. Provisioning only
#    has to put a working binary on the device.

# 2. Install the target app, but do not launch it
adb -s emulator-5554 install -r target.apk

#    The next step needs the package name, which the filename need not resemble
#    — one real sample ships as Gov-Services.apk, installs as com.k4m2p9.zx7qwd
#    and labels itself "Gov Services". Ask the file, or ask the device:
aapt dump badging target.apk | awk -F"'" '/^package/{print $2}'   # build-tools
adb -s emulator-5554 shell pm list packages -3                    # or diff this

# 3. Run — spawns the app and hooks it from the start
python3 sockstack.py --device emulator-5554 \
    --package com.example.app --output ./run --duration 200

#    For a sample with no launcher activity — most RATs — spawning gets you a
#    process that dies immediately. Start it by hand and attach instead:
#      …--attach
#    Root evasion is off by default (it crashes friTap on Android 14); a sample
#    that really checks for root needs …--anti-root. See docs/GOTCHAS.md.

# 4. …while it runs, drive the app so it actually reaches the network
adb -s emulator-5554 shell input tap 540 1800
```

Re-generate the decryption and summary from artifacts you already have:

```bash
python3 sockstack.py --postprocess-only --output ./run
```

Reports are named after the run they describe (`summary_20260725T215003Z.md`), and
the heading comes from `run_manifest.json` rather than from anything passed on the
command line, so a report cannot misstate which target it belongs to.

## Options

```
--device            adb/Frida device id (required unless --host)
--package           target package name, or a local command with --host
--output            output directory                                    [required]
--duration          collection window in seconds (default 200)
--attach            attach to a running app instead of spawning it
--host              run against a local process — for verifying the toolchain
--tcpdump           path to tcpdump on the device if it is not in PATH
--script            tracer script path
--anti-root         turn friTap's root evasion on (off by default: crashes on Android 14)
--no-anti-root      force friTap's root evasion off
--keep-device-artifacts   leave the capture file on the device
--postprocess-only  only decrypt and summarize an existing --output
--no-postprocess    capture only
```

## Web UI (optional)

```bash
python3 ui/server.py            # http://127.0.0.1:8722
```

Standard library only — nothing to install, and nothing added to the CLI's
dependencies for people who do not want it. Every run it starts is an ordinary
`sockstack.py` invocation into an ordinary output directory, so nothing done here
becomes unavailable without it.

**Launch screen.** Attached devices with what they actually are — Android
version, ABI, build type, whether `frida-server` is up — and devices that are
present but unauthorized listed as such rather than omitted. Alongside them, past
runs found under a directory you name, described by what they recorded: call
sites, records, whether the Java bridge worked. Never "clean" — a run that found
nothing and a run whose bridge failed look identical from outside, and only one
of those is reassuring.

**Connecting a stand.** Under the device list: an address (`host`, or `host:port`
— 5555 is assumed) and **connect**, which is `adb connect`. Its own sentence is
shown either way, and it is judged by that sentence rather than by its exit
status, because `adb connect` exits 0 while printing "failed to connect to…".
Wireless debugging on Android 11+ pairs first, on a different port with a
six-digit code the device shows you; that lives behind **pair a wireless
device…** on the same card. Devices connected over the network carry a ✕ to
disconnect them; USB ones do not, since there would be nothing to disconnect.

**A device on a host you reach with an SSH key.** Do not type that host into the
connect field: adb has no authentication, and neither has this page. Forward a
port and connect to the near end. **the device is on a remote host…** on the same
card prints the three commands with the host already filled in:

```bash
# best: run the panel where the device is, forward the panel
ssh -i ~/.ssh/id_ed25519 -L 8722:127.0.0.1:8722 user@stand   # then: python3 ui/server.py

# or keep the panel here and forward the device's adb port, then connect 127.0.0.1:5555
ssh -i ~/.ssh/id_ed25519 -N -L 5555:127.0.0.1:5555 user@stand

# or forward the whole adb server; every device on that host appears in the list
ssh -i ~/.ssh/id_ed25519 -N -L 5038:127.0.0.1:5037 user@stand
ANDROID_ADB_SERVER_PORT=5038 python3 ui/server.py
```

The card shows which adb server it is talking to, so the third form can be seen
to have worked. It comes with a caveat worth reading before using it: a client
whose version differs from the server's kills that server — over a tunnel, the
remote one. See `docs/GOTCHAS.md`.

The panel will not run `ssh` for you, and that is deliberate: it has no login of
its own, so an SSH button would lend your key to anyone who opened the page.

**Installing the target.** Second card on the launch screen: drop an APK on it,
or give a path already on the analysis host. The upload matters when the browser
is not on the machine holding the device — the usual shape, a laptop tunnelled
into the stand — and the file is sent to the host running `adb`, not to anywhere
else. Installing from here is worth a step of its own for one reason: the package
name. It is read from the difference in `pm list packages` either side of the
install and filled into the target selector, and the APK's filename would not
have told you it. The same field sits above the screen mirror for an APK you
decide to install mid-session.

**Language.** `EN · RU` in the top bar switches the interface and is remembered.
Only the interface: adb's output, sockstack's log and the findings text stay in
the words the tool produced them in, because a translated error message is no
longer the error message.

**Workspace.** The device screen on the left, the findings in the middle, the log
along the bottom.

The screen is the reason to use it at all. Reaching the network means touching
the app, and from a terminal that is `input tap 797 1284` — coordinates obtained
by dumping the view hierarchy, parsing XML and computing a centre by hand, slow
and wrong often enough to cost a run. Here the clickable nodes are outlined by
their resource id, so you click `installUpdateBtn` rather than aiming at a point,
and the click still lands on a device with a different screen size.

The findings panel calls the CLI's own `summarize_trace`. There is no second
implementation of "attributed", so the page and the written report cannot drift
apart. Peer colour says **how well the call site is known** — green when the
stack names application code, neutral for library-only and native threads, amber
for destinations nobody examined and for a Java bridge that was not working. It
does not say how suspicious an address looks: this tool cannot tell a C2 from a
CDN, and a red badge implying otherwise would be exactly the kind of confident
wrong answer the rest of the design works to avoid.

**It has no authentication and it controls the device** — it accepts file
uploads, installs APKs and runs adb commands for anyone who can reach it. It binds to loopback; reach it
from another machine with a tunnel rather than `--bind`:

```bash
ssh -L 8722:127.0.0.1:8722 user@analysis-host
```

## Emulator vs physical phone

| | Emulator (userdebug) | Physical phone (Magisk) |
|---|---|---|
| Root | `adb root`, shell is root | `su -c` only — detected automatically |
| `tcpdump` | already in `/system/bin` | push a static binary (`setup-device.sh`) |
| `frida-server` | match the emulator's ABI | match the **phone's** ABI |
| Anti-emulation | may refuse to run | required for emulator-aware samples |

## Limitations

Read these before trusting an empty result.

- **Only libc is hooked.** A runtime that issues raw syscalls — Go/gomobile, a
  statically linked payload — never passes through it, so there is nothing for the
  tracer to record and nothing to attribute. The tool does not pretend otherwise:
  every device run also polls the kernel's `/proc/net/{tcp,tcp6,udp,udp6}` for
  sockets owned by the target's own UID, and any destination found there but
  missing from the tracer is reported under **Traffic the tracer has no record
  of**. That is sampled every two seconds, so a short-lived connection can still
  slip between polls; the check turns a silent blind spot into a named one, it
  does not remove it. It reports its own state as well — an unresolved UID, an
  unreadable `/proc/net`, or a UID shared with other packages — so that a clean
  result cannot be confused with a check that never ran.

  `--ftrace` closes the sampling half of that gap: it streams
  `sock:inet_sock_set_state` off the kernel through a tracing instance of its
  own, so a TCP connection opened and closed between two polls arrives as
  events rather than not at all. Root, and nothing else — no eBPF toolchain, no
  BTF, no compiler. **TCP only**: UDP has no state machine, so datagram
  destinations still come from polling alone and this source's silence about
  them means nothing. The summary names how many destinations the poll missed,
  which is the measurement worth having before reaching for anything heavier.
  What it does not do is attribute: the kernel knows pid, comm and uid, never
  `com.target.SyncWorker.run`. Attribution stays with the tracer, and no
  kernel-side source will change that.
- **Native threads have no Java stack.** Cronet's network thread, JNI code and
  non-JVM runtimes produce records with no attribution. Those peers are listed
  separately in the summary rather than silently dropped — and separately from
  peers the tracer merely did not examine, which is a different finding.
- **Attribution is sampled, not exhaustive.** At most 8 *distinct* call sites are
  recorded per destination — counted per `(operation, address, port)`, so a peer
  reached by several operations can yield more — with a ceiling of 48 stack walks
  each, and at most 500 records per run. Totals in `socket_trace_counts.json` stay
  complete regardless, and any peer that was cut short by the budget is named in
  the summary. Walking every stack is what made the original instrumentation
  unusable.
- **Under a SOCKS or HTTP proxy, DNS correlation breaks.** Entries below the
  divider are marked **target** by matching the address against what the tracer
  saw the target contact. If the app is pointed at a proxy, it connects to the
  proxy's address while resolving names elsewhere, so the two never match and
  every DNS entry is reported as another process. A *transparent* redirect —
  iptables below the emulator, which is how the malware run above was done —
  keeps real destinations in both places and the marking holds.
- **The packet capture is device-wide.** DNS, SNI and HTTP are read from it, so
  they can include other applications' traffic. Each of those entries is marked
  **target** when its address matches one the target was seen to contact — by the
  tracer, or by the kernel cross-check above. Unmarked means neither saw it, which
  is usually another process and is never proof of one: read it as "not
  attributed", not as "proven unrelated".

## Maturity

Be precise about this, because it is a forensic tool.

**Verified end to end on a device with this exact build (2.2.0).** On a headless
Android 14 x86_64 emulator, one `sockstack.py` invocation against F-Droid — an
ordinary OkHttp app — spawned the target, captured with on-device `tcpdump`,
collected the TLS secrets, injected them with `editcap`, extracted decrypted
bodies, and recorded 17 socket operations with `java=16, not-walked=1`. It
attributed **eight distinct call sites, four of them reaching the same host**.
The manifest's `tracer_script_sha256` matches the shipped bundle, and the
session stopped cleanly.

Those four are the regression evidence for the de-duplication fix: they share
identical `libcore`/`java.net` frames at the top of the stack, which is exactly
what the previous build hashed — so it would have collapsed them into one
record and reported a single code path where there are four.

**Verified against live Android malware, with this build.** An Android RAT with
no launcher activity, attached to after the system started it through its
AccessibilityService, all egress forced through Tor. 47 socket operations,
`java=12, native-thread=35`, **no record left unexamined** — and **seven distinct
call sites in the sample's own obfuscated package reaching its C2**, plus more
for its DNS probes. The report at the top of this README is the same sample's
attribution section from an earlier capture, which found three; the
de-duplication and budget fixes are the difference.

**Measured under load.** A 100 MB transfer read one kilobyte at a time — 26,294
socket operations through the hooks — took 0.43 s uninstrumented and 1.22 s
under the tracer, and the target completed normally. That is ~30 µs of overhead
per hooked operation, on a workload that is nothing but syscall churn. Two
caveats: this was `--host`, so it measures the hooks, the descriptor cache and
de-duplication, not the Java bridge; and the expensive part — walking a stack —
is separately capped at 48 walks per destination, which is why it cannot scale
with traffic.

**Verified on Linux against a local process (`--host`) and by unit tests:** the
friTap plugin channel; hook coverage; TCP and UDP peers including unconnected UDP
and IPv6; that the instrumentation does not kill the target; early-exit detection
and complete artifact writing when the target dies mid-run; sockaddr parsing and
IPv6 formatting; the summary, attribution and `stack_source` reporting rules.

**Known-weak areas.** Attribution coverage depends on the target — a large share
of native-thread records is normal for an app whose networking sits in native
code. Spawn mode is unreliable for apps with no launcher activity, which is most
RATs. friTap's root evasion is off by default because it crashes friTap on
Android 14, so a sample that genuinely checks for root needs `--anti-root` and
will hit that crash; both are covered in [docs/GOTCHAS.md](docs/GOTCHAS.md). The physical-phone path is implemented but has
had far less use than the emulator path.

Reports from real runs are very welcome.

## The agent

Frida 17 removed the built-in `Java` global — the bridge is now an npm package
that must be bundled into the agent. Without it the tracer runs, hooks
everything, and reports every record as native: the feature disappears with no
error at all. So the agent is a compiled artifact:

```
agent/src/index.js   tracer + `import Java from 'frida-java-bridge'`
agent/src/addr.js    pure address parsing (unit-tested under plain node)
scripts/frida/socket_trace.bundle.js   built output, shipped in the tree
```

Rebuild after changing anything under `agent/src/`:

```bash
cd agent && npm ci && npm run build
```

`npm ci` installs exactly what `package-lock.json` pins. The build is
byte-for-byte reproducible, and `tests/test_bundle_fresh.py` fails if the shipped
bundle no longer matches `agent/src/` — without that check an edit that was never
rebuilt would leave the tracer running the old behaviour while the sources
describe the new one.

The agent reports which state it is in — a working bridge, a Java runtime with a
broken bridge, or a process with no Java at all — and the summary prints it. A
missing bridge is an error, never a quiet "native".

## `stack_source`: why a record has the stack it has

Every record in `socket_trace.json` carries a `stack_source`. It exists because
"there was no Java code here" and "we did not manage to look" are different
findings, and a forensic tool must not merge them. The summary groups
unattributed peers by these values and never describes any of them except
`native-thread` as native code.

| `stack_source` | Meaning | Reported as |
|---|---|---|
| `java` | a Java stack was captured | attributed — or `framework-only` if the stack names no application code |
| `native-thread` | the calling thread had no JVM attached | **genuinely native** — Cronet, JNI, a non-JVM runtime |
| `not-walked` | the per-destination budget was already spent | not examined; further call sites may exist |
| `no-bridge` | a Java runtime is present but the bridge failed to load | attribution unavailable — a broken run, not a native one |
| `stack-error` | the walk itself threw | attribution unavailable; the summary prints the exception |
| `no-runtime` | the process has no Java runtime at all | expected under `--host` |

Anything unrecognised — an older artifact, a newer agent — is reported as
`unknown` and ranked as *less* certain than `native-thread`, so a value this
version of the summary does not understand can never be read as "native".

A peer that is attributed anywhere never appears in the unattributed lists. If
some of its operations were left unwalked it is instead flagged as attributed but
not exhaustively examined.

## Tests

No device or Frida installation needed:

```bash
python3 -m unittest discover -s tests -v     # runner logic, report logic, bundle freshness
node tests/test_agent_addr.mjs               # sockaddr, IPv6, call-site signatures
```

What they do and do not cover, since this matters more than the count:

- They **do** cover the reporting rules that decide what the analyst is told —
  every `stack_source` value, the precedence between them, and the rule that a
  peer is never both attributed and called native. Those tests exist because the
  summary once asserted both about the same C2.
- They **do** cover call-site signatures, including two stacks that differ only
  below the framework plumbing — the case that silently discarded call sites.
- They **do not** cover the bridge itself. Capturing a real Java stack needs a
  real JVM: `--host` against `curl` proves only that the tracer runs. Attribution
  has to be regression-tested against a live app on a device, and that step is
  manual.

## Gotchas

Everything that cost real debugging time is in [`docs/GOTCHAS.md`](docs/GOTCHAS.md).

## Handle the output carefully

A run directory holds TLS session secrets and decrypted traffic. It can expose
credentials, tokens and personal data — including data belonging to people who are
not the subject of your analysis — and may contain material you are not entitled to
redistribute. sockstack creates the directory `0700` and `.gitignore` keeps it out
of the repository; the rest is on you.

## Licence

AGPL-3.0 — see [`LICENSE`](LICENSE). The socket tracer is a derivative of the
PiRogue Tool Suite's instrumentation; friTap is a GPL-3.0 dependency. Attribution
and licensing details are in [`NOTICE`](NOTICE).
