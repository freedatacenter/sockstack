# A walkthrough

From an empty directory to a report that names the code which opened a socket.
Every command here was run against a real device; the outputs are quoted as they
came out, including the parts that look like failures and are not.

If you only want the option list, it is in the README. This document is about
what to do in what order, and how to tell a good run from a bad one.

---

## Step 0 — decide whether this tool answers your question

sockstack records, for each socket operation, the Java call stack that produced
it. It is at its best on code that opens sockets from its own threads —
hand-written network layers, which is what most Android malware has.

It is least useful on apps built on a mature asynchronous HTTP client. OkHttp
performs requests on its own thread pool, so at the moment of the system call
the stack contains okhttp and okio frames and nothing else: the application code
that queued the request ran earlier, on another thread. You will get
`(library only)` entries. That is a true answer, not a failure — but if it is
the only answer you need, a simpler tool will do.

---

## Step 1 — install the host side

```bash
pip install -r requirements.txt          # friTap 2.x, which pins Frida to 17.x
# Debian/Ubuntu: apt install tshark android-tools-adb
# macOS:         brew install wireshark android-platform-tools
```

`tshark` and `editcap` come from Wireshark and are used only for the decryption
and summary steps. Without them a run still captures; it just stops before
producing readable output.

Node is **not** required. The Frida agent ships pre-built in the tree; Node is
needed only if you want to rebuild it.

---

## Step 2 — check the toolchain before involving a device

This runs against an ordinary local process. It proves that friTap starts, that
the plugin loads, that libc hooks install, and that the summary is written —
without a device, an emulator or an APK in the picture.

```bash
python3 sockstack.py --host \
    --package "/usr/bin/curl -s https://example.com" \
    --output ./selftest --duration 30
```

What a healthy run says:

```
[*] Plugin sockstack-socket-trace: script loaded (order=after)
[+] socket tracer active on libc.so.6: __read_chk, close, connect, dup2, dup3,
    read, recv, recvfrom, recvmsg, send, sendmsg, sendto, write
[!] not hooked (absent from this libc): __write_chk
[+] socket_trace.json: 11 records
```

Three things to read there:

- **`order=after`** — the plugin loaded after friTap's own script, which is the
  order it needs.
- **the "not hooked" line is normal.** Not every libc exports every symbol. The
  tracer reports what it could not hook instead of pretending it hooked it.
- **records > 0** — operations are actually being intercepted.

Two lines in this run look like problems and are not:

```
[!] friTap did not stop within 30s — continuing anyway
[!] decryption: not attempted: no traffic.pcap in this directory
```

The first is friTap's session teardown on a target that already exited; the same
message tells you *all artifacts were written before the stop was attempted*, so
nothing is lost. The second is expected in `--host` mode, which has no packet
capture — capture happens with `tcpdump` on the device.

Open `selftest/summary_*.md` and confirm the attribution section reads:

```
Java bridge: not applicable (no Android runtime in this process)
Record stack sources: no-runtime=11
```

For `curl` that is the correct answer. If you see `unknown` instead, the tracer
does not know why it has no stack, and that is worth investigating before you
trust a real run.

---

## Step 3 — provision the device

You need root: an emulator (`adb root`) or a phone with Magisk.

```bash
./setup-device.sh emulator-5554 ./frida-server-17.2.0-android-x86_64
adb -s emulator-5554 reboot
```

The architecture in that filename is **Frida's, not Android's**. A device
reporting ABI `arm64-v8a` needs `frida-server-…-android-arm64`. The script prints
the device ABI, pushes the binary, then *starts it and waits* — so a mismatched
binary fails here, next to the file you just chose, rather than twenty seconds
into a capture:

```
[+] device ABI: x86_64
[+] verifying frida-server actually runs on this device
[+] frida-server is up and stays up
```

The reboot is for a persist property the script sets (`persist.traced.enable=0`),
which works around a perfetto crash that kills target processes at launch on some
Android 14 images.

You do not have to start frida-server yourself on later runs: sockstack launches
it on demand, and restarts it if a previous session left it wedged.

---

## Step 4 — identify the target, then install it

Step 5 needs the target's **package name**. Get it first: the filename tells you
nothing, and a plausible guess simply fails.

### Why you cannot guess it

One sample from a current campaign, as three different strings:

| | |
|---|---|
| file name | `Gov-Services.apk` |
| package name | `com.k4m2p9.zx7qwd` |
| app label on screen | `Gov Services_v14.2` |

The file name is whoever saved it; the package name is the identity Android
uses; the label is what the victim sees. They are chosen independently, and
malware has every reason to make the first and third look legitimate while the
second is machine-generated noise.

### Ask the file — preferred, and needs no device

With Android build-tools present:

```bash
aapt dump badging target.apk | awk -F"'" '/^package/{print $2}'
```

Knowing the name before the APK touches the device is worth a little effort: you
can confirm what you are about to install, and you have the name ready if the
app crashes on launch or uninstalls itself.

### Install

```bash
adb -s emulator-5554 install -r target.apk
```

Leave it un-launched. The next step spawns it, so that hooks are in place before
its first instruction — including whatever it does in `Application.onCreate`,
which is where a lot of interesting behaviour lives.

### Ask the device — if you have no build-tools

Third-party packages sorted by install time put the one you just installed last.
No snapshot taken beforehand, no extra tooling:

```bash
for p in $(adb -s emulator-5554 shell pm list packages -3 | sed 's/package://' | tr -d '\r'); do
    t=$(adb -s emulator-5554 shell dumpsys package $p | grep -m1 firstInstallTime | tr -d '\r' | sed 's/.*=//')
    echo "$t  $p"
done | sort
```

```
2026-07-26 10:34:34  org.fdroid.fdroid
2026-07-26 13:07:41  com.samplevpn.core
2026-07-26 21:05:33  com.k4m2p9.zx7qwd        <- just installed
```

### When you need the label instead

`--package` takes the **package name** when spawning, which is the normal case.

With `--attach` it is different: Frida identifies the main process of a
foreground app by its **label**, so `--package com.android.chrome` reports
"unable to find process" while Chrome is plainly on screen — it is listed as
`Chrome`. When an attach fails, the runner prints the processes the device is
actually offering, matched against what you asked for, so you can pick the right
string instead of guessing.

---

## Step 5 — run

`--package` is the package name from Step 4, not the filename you installed:

```bash
python3 sockstack.py --device emulator-5554 \
    --package com.k4m2p9.zx7qwd --output ./run --duration 200
```

While it runs, **drive the app**. A tracer attached to an idle app records an
idle app. Tap, scroll, log in — whatever makes it reach the network:

```bash
adb -s emulator-5554 shell input tap 540 1800
```

Two variations you will need sooner or later:

- **`--attach`** for a sample with no launcher activity — most RATs. Spawning one
  gets you a process that dies immediately; start it by hand and attach instead.
- **`--anti-root`** for a sample that actually checks for root. Root evasion is
  **off by default** because it crashes friTap on Android 14. Turn it on only
  when the target demands it, and expect the crash if it does not.

A healthy run ends like this:

```
[+] socket_trace.json: 17 records
[+] pcap: ./run/traffic.pcap (4681430 bytes)
[+] decryption: keys injected into the capture
[+] summary: ./run/summary_20260726T203955Z.md
    peers: 3, attributed call sites: 12, DNS: 2, SNI: 2, HTTP requests: 15
```

---

## Step 6 — read the report

Open `summary_<timestamp>.md`. It is ordered so that the most trustworthy
material comes first.

### Run status

```
- Tracer records: 17
- Java bridge: available (call-stack attribution active)
- Record stack sources: java=13, not-walked=4
```

`Java bridge: available` is the line that matters. Without it there is no
attribution at all, and everything below will say so.

`Record stack sources` accounts for **every** record. The numbers add up to the
record count by construction — if they did not, records would be vanishing
silently.

### Call-stack attribution

This is the point of the tool:

```
- `37.218.243.72:443` ← (library only) — via `okio.InputStreamSource.read(JvmOkio.kt:93)
    → okio.RealBufferedSource.request(RealBufferedSource.kt:63)
    → okhttp3.internal.http2.Http2Reader.readConnectionPreface(Http2Reader.kt:73)`
```

Read it as: *this address was contacted from this code path*. Two conventions
worth knowing:

- **`(library only)`** means a real Java stack was captured but it names no
  application code — only networking libraries. Common with asynchronous HTTP
  clients (see Step 0). The library chain is still shown, because which part of
  okhttp did it is a real distinction: connecting, sending headers and finishing
  a request are three different events.
- **the `→` chain grows only as far as it must.** Entries are shown with a few
  frames; when two entries would otherwise print identically, the display
  reaches deeper until they differ. If you see a long chain, it is because
  something else shared its beginning.

Malware with a hand-written network layer looks different — the stack names its
own classes, obfuscated but its own:

```
- `203.0.113.47:9999` ← `k7v2p9x4m1qz.la0.c(Unknown Source:68)`,
                        `k7v2p9x4m1qz.ja0.j(Unknown Source:134)`
```

### Unattributed

Destinations with no usable call stack, grouped by **why**, never by guesswork:

| Reason | What it means for you |
|---|---|
| `attribution-unavailable` | the Java bridge was not working — **not** evidence the call site is native |
| `unknown` | the tracer did not record a reason; treat as unexamined |
| `not-examined` | never stack-walked: the per-destination budget was spent elsewhere, so more callers may exist |
| `framework-only` | a stack was captured but contains only framework frames |
| `native-thread` | genuinely native: no JVM on that thread — Cronet, JNI, a non-JVM runtime |
| `no-runtime` | the process has no Java runtime at all |

When a destination's records disagree, the report shows the reason that concedes
the most ignorance. Presenting an unexamined destination as "native code" would
be a confident wrong answer, and for an investigation that is worse than none.

Watch for this line, too:

```
Attributed above, but not exhaustively: some operations to these peers were
never stack-walked, so further call sites may exist.
```

It means the list of call sites for that peer is a floor, not a total.

### Everything below the horizontal rule

The tracer sees **only the target process**. The packet capture is **device-wide**.
So the DNS, SNI and HTTP sections mark each entry:

```
- `f-droid.org` — 2 — **target**
- `n7k2q9x4m1v8.backend.example` — 1 — other process
```

`target` means the tracer itself saw the process contact that address. Unmarked
entries were resolved or contacted by something else on the device. On a device
where you are detonating malware, this distinction is the difference between
attributing a C2 to your sample and attributing your neighbour's traffic to it.

---

## Step 7 — re-generate the report without re-capturing

A capture is expensive and unrepeatable; analysis is neither.

```bash
python3 sockstack.py --postprocess-only --output ./run
```

The report keeps the **same filename**, because its timestamp comes from
`run_manifest.json` — the run it describes — not from the clock. A report cannot
drift away from the capture it belongs to.

Run this in a directory that still has `traffic.pcap`. Post-processing a
directory without it will happily produce a summary with no DNS, SNI or HTTP
sections, because there is nothing to read them from.

---

## When something goes wrong

| Symptom | Cause |
|---|---|
| `no root on the device` | emulator: `adb -s <id> root`; phone: Magisk |
| `could not bring frida-server up` | almost always the wrong architecture — the message names the device ABI |
| `--package com.foo.bar` not found in `--attach` | Frida matches the app **label**, not the package; the runner suggests close matches |
| target dies instantly on launch | the perfetto workaround needs a reboot after `setup-device.sh` |
| target dies with `--anti-root` | expected on Android 14 — leave root evasion off unless the sample needs it |
| all records `attribution-unavailable` | the Java bridge failed; check `socket_trace_meta.json` for `java_bridge_error` |
| `ReferenceError: 'Java' is not defined` in your **own** Frida script | Frida 17 removed the built-in `Java` global; it has to be bundled with `frida-compile` (this is why the agent here ships as a bundle) |

`socket_trace_meta.json` is the first place to look when a run is puzzling: it
records which functions were hooked, which were absent, which failed, whether a
Java runtime and bridge were present, and any tracer errors.

---

## What this tool will not tell you

- **Who queued an asynchronous request.** The stack belongs to the thread making
  the system call. With OkHttp, Cronet or any thread-pool client, that is the
  transport, not the caller.
- **Anything about a process it is not attached to.** Traffic from other
  processes appears in the capture and is marked as not-target; it is never
  attributed.
- **Every call site, exhaustively.** Stack walking is budgeted per destination
  so that a chatty socket cannot starve the run. When the budget bounds a result,
  the report says so rather than presenting a partial list as complete.
- **Anything from a target with no `INTERNET` permission**, which cannot open a
  socket at all. Droppers whose only job is to install a second stage are a real
  example: trace the stage that has the permission.
