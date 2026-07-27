# Field notes & gotchas

Everything below cost real debugging time. Collected here so it costs you none.

## Frida 17 removed the `Java` global — bundle the bridge or lose everything

This is the one that cost the most. In Frida 16 a script could just use `Java`.
Frida 17 moved the bridges out of the runtime into npm packages, so on 17
`typeof Java === "undefined"` and any `Java.…` reference throws
`ReferenceError: 'Java' is not defined` — *inside the hook*, at runtime.

The failure is silent in the worst way. A tracer that guards with
`if (typeof Java === 'undefined') return null;` keeps running, hooks everything,
collects peers, and labels every single record "native". Nothing errors. A whole
detonation against real malware produced 33 records, every one of them
unattributed, and the run looked healthy.

Two things are needed:

1. **Bundle the bridge.** `npm i frida-java-bridge`, `import Java from
   'frida-java-bridge'`, build with `frida-compile`. The agent stops being a
   standalone `.js` and becomes a build artifact.
2. **Check it actively, and keep the states apart.** "This thread has no JVM
   attached" and "the bridge never loaded" look identical downstream and mean
   completely different things. Detect whether the process has an Android runtime
   at all (look for `libart.so` among the loaded modules) and, if it does but the
   bridge is not available, emit an error — do not fall through to "native".
   Recording the distinction is only half of it; see the next section for the
   half that gets lost on the way to the report.

## "No Java stack" is four different findings — do not let them merge

The bridge fix above is only half the job. Once the agent knows *why* a record
has no stack, the reporting layer has to say so, and it is very easy for that
knowledge to die on the way out.

sockstack shipped exactly that bug. The agent set `stack_source` correctly; the
summary ignored it and decided from the frames alone:

```python
app, network = classify_stack(rec.get('stack'))
if not app and not network:
    native_only.add(peer)        # "native code — Cronet, JNI, or a non-JVM runtime"
```

A record nobody stack-walked has no frames. So does a record from a thread with
no JVM. So does a record whose walk threw. The report called all of them native
code. In a real run against malware, the same C2 address appeared **under
call-stack attribution and under "native code" in the same document** — because
one of its operations was attributed and another had been skipped by the
stack-walk budget.

Three rules keep it honest:

1. Decide from the tracer's `stack_source`, never from the absence of frames.
   Only the tracer knows whether it looked.
2. When a peer's records disagree, report the reason that concedes the most
   ignorance. "We did not look" must outrank "there was nothing to see", and an
   unrecognised value must outrank both.
3. A peer that is attributed anywhere must never appear in an unattributed list.
   If some of its operations were skipped, say *that* instead.

A Java stack made only of `java.*`/`libcore.*` frames is a fourth case again: it
is a real stack, it proves the call site is not native, and it still does not
name the caller.

## Budget the stack walks by what you keep, not by what you try

The natural way to bound stack walking is a counter per destination,
decremented on every walk. It quietly destroys the result.

Most operations to a host come from the *same* call site, so they produce
identical stacks and are discarded by the deduplicator. Charging them anyway
means the budget is spent on duplicates: with a cap of 8, a real run burned 6
credits on repeats of one caller and then marked genuinely different callers to
the same C2 as "not walked". The tool answers "how many distinct code paths
reach this host" — and the budget was optimised to lose exactly that.

Count *distinct call sites kept*, and put a separate, much higher ceiling on
walks performed so a hot destination still cannot cost unbounded work.

## Frida may not know the app by its package name

`--attach --package com.android.chrome` fails with
`BackendProcessNotFoundError: unable to find process with name 'com.android.chrome'`
while Chrome is plainly running and `pidof com.android.chrome` answers. Frida
names the main process of a foreground app by its **label**, so that process is
offered as `Chrome`. Its helper processes keep the package name
(`com.android.chrome:privileged_process0`), which makes the failure look even
stranger: some of the app's processes are findable and the one you want is not.

It does not bite every target — a malware sample with no launcher entry and no
label showed up under its package name — which is exactly why it is confusing
when it does.

sockstack prints the candidates on this error rather than leaving you to guess:

```
[!] friTap failed to start: BackendProcessNotFoundError: unable to find process ...
    Frida knows these processes by a different name — try one of:
      --package "Chrome"    (pid 8508)
```

Note also that a browser does its networking in a *different* process than the
one carrying the UI, so attaching to the label gets you the browser process and
possibly no socket activity at all. Check `--package "<pkg>:privileged_process0"`
too when a run comes back empty.

## friTap's anti-root breaks the session on Android 14

`FriTap(...).anti_root(True)` throws inside friTap's own script on Android 14 —
`TypeError: cannot read property 'indexOf' of undefined`, followed by "Exiting
due to script error", and the session never starts. Not a bug in your plugin;
nothing to fix on your side.

It is not attach-specific. It was first hit while attaching to a sample on an
arm64 emulator, and the natural conclusion — that attaching was the trigger —
was wrong: it reproduces just as reliably on **spawn**, on a freshly built
x86_64 Android 14 emulator, against an ordinary app. Two different modes, two
architectures, two machines.

sockstack therefore leaves root evasion **off by default** and `--anti-root`
turns it on. A default that reliably prevents the tool from starting is not a
useful default, and attaching to an already-running app never needed it anyway:
whatever root checks the app performs, it has already performed. A sample that
genuinely refuses to run under root is the one case that needs the flag — and
that case still hits this crash on Android 14.

## Spawn is useless for apps with no launcher activity

A RAT typically has no launcher icon. In the sample this tool was validated
against, the only `MAIN` activity carried category `INFO` rather than `LAUNCHER`,
so `cmd package resolve-activity` returns "No activity found" and spawning by
package name gets you a process that immediately dies — while the *real* malware
process is started separately by the system when its AccessibilityService is
bound, under a different pid.

Symptom: the collection loop reports the target ended within seconds, and the
capture contains nothing while the app is demonstrably running. Use `--attach`
against the live pid. Enabling the service is what starts it:

```bash
adb shell settings put secure enabled_accessibility_services <pkg>/<pkg>.<Service>
adb shell settings put secure accessibility_enabled 1
```

That behaviour — no launcher, respawn under a system service — is worth recording
as a finding about the sample, not just a workaround for the tool.

## friTap's `on_message()` is not for plugin scripts

The obvious-looking way to receive messages from a custom Frida script is
`FriTap(...).custom_script(path).on_message(cb)`. It never fires, and nothing tells
you why: **`on_message()` delivers decrypted chat messages** (Signal and similar),
not raw `send()` payloads from your script.

The supported extension point is the plugin API:

```python
from friTap.plugins import ScriptPlugin, ScriptLoadOrder

class MyPlugin(ScriptPlugin):
    @property
    def name(self): return "my-plugin"
    @property
    def version(self): return "1.0.0"
    def get_script_source(self, context): return open("my.js").read()
    def on_script_message(self, message, data):   # <- your send() arrives here
        ...

FriTap(target).add_script_plugin(MyPlugin()).start()
```

You also get `post_to_script()` for the return direction, lifecycle hooks, and
`load_order`. There is no need to reach into `SSL_Logger` — or into
`ScriptPlugin._scripts`, which is just as private.

## Finalize everything *before* stopping the session

`session.stop()` can block indefinitely. friTap's detach path calls back into
Frida from the callback thread while the main thread is inside `script.unload()`,
and the two deadlock; on other paths it can terminate the process outright. Either
way, anything your code does *after* `stop()` may never run.

Write your artifacts first, stop afterwards, and run the stop on a thread with a
timeout. sockstack also appends every record to a `.jsonl` as it arrives, so even
a hard kill leaves the collected data on disk.

## `is_running` does not mean the target is alive

`FriTapSession.is_running` reflects friTap's own logger, not the target process. A
target that exited seconds ago still reports `True`, so a collection loop that
trusts it will sit out the entire `--duration` and then hit the stop hang above.

Use a signal that comes from inside the target instead. sockstack's tracer emits a
counts message on a timer; when the beats stop, the process is gone.

## What the instrumentation actually costs

Worth knowing before you distrust a slow run. Measured on a 100 MB loopback
transfer read a kilobyte at a time — 26,294 hooked socket operations:

| | |
|---|---|
| uninstrumented | 0.43 s |
| under the tracer | 1.22 s |

Roughly 30 µs per hooked operation, and the target finishes. The cost is in
entering JS from the native hook, so it is paid per *operation* regardless of
how much data each one moves: a few large reads are nearly free, a great many
small ones are not.

Stack walking is the expensive part and does not scale with traffic — it is
capped per destination, so a busy socket cannot buy an unbounded number of
`getStackTrace()` calls. That cap is the reason the numbers above stay flat.

## A socket tracer will kill the target if you hook by prefix

The natural implementation — enumerate libc exports, keep the ones starting with
`connect`/`send`/`recv`/`read`/`write`, hook them all — also catches `readahead`,
`readv`, `pwrite64` and `sendfile`. Combined with a `Socket.type(fd)` call in every
`onEnter`, that means a socket query on **every file I/O operation** in the process.
A busy target dies within seconds, and it looks like an unstable app or a flaky
emulator rather than the instrumentation.

What makes it survivable: match export names **exactly**; cache descriptors learned
at `connect()` time and consult that cache before any socket query; de-duplicate;
and cap both the stored records and the number of stack walks per peer.

## `connect()` has no peer address yet — and UDP has none at all

In `onEnter` for `connect()` the connection is not established, so
`Socket.peerAddress(fd)` returns `null`. Read the destination from the `sockaddr` in
`args[1]` instead. Miss this and you lose the first contact with every host.
(Symptom: your trace contains DNS and nothing else.)

The same applies more broadly. `Socket.peerAddress()` only answers for *connected*
sockets, so unconnected UDP — DNS, QUIC, HTTP/3 — is invisible through it. Take the
address from the arguments:

| call | where the address is | when |
|---|---|---|
| `connect` | `args[1]` | onEnter |
| `sendto` | `args[4]` | onEnter |
| `sendmsg` | `msghdr.msg_name` via `args[1]` | onEnter |
| `recvfrom` | `args[4]` | **onLeave** — the kernel fills it on the way out |
| `recvmsg` | `msghdr.msg_name` | **onLeave** |

`send`/`recv` carry no address and must fall back to the cache.

## File descriptors are recycled — evict them

If you gate `read`/`write` on a set of known socket descriptors, you must hook
`close()` and delete the entry, and handle `dup2`/`dup3`. The kernel hands out the
lowest free descriptor, so a socket to `1.2.3.4:443` closes and the number comes
back as a log file or a *different* socket. Without eviction every subsequent
`read`/`write` is attributed to the previous owner — a confident, plausible, wrong
answer, which for an investigation is worse than no answer.

## `full_capture` needs root and fails quietly

friTap's `--full_capture` opens a raw socket. Without the privileges for it you get
a `PermissionError` in the log, the capture thread dies, **and the pcap file is
never created** while the run otherwise looks successful. sockstack does not use
it: the raw capture is a plain `tcpdump` on the device and the keys are injected
afterwards with `editcap --inject-secrets`.

## `su -c` needs the whole command as one argument

On a Magisk phone, `adb shell su -c "cmd || other"` is tokenised by the *device*
shell before `su` runs. The operator applies to `su` itself, so the right-hand side
— and any redirection — executes as the unprivileged shell user while appearing to
run "under su". A redirect to a root-only path then fails for no visible reason.
Quote the entire payload so it stays inside `su`:

```bash
SU() { local p=${1//\'/\'\\\'\'}; adb -s "$SERIAL" shell "su -c '$p'"; }
```

The direct-root branch on an emulator does not have this problem, which is why it
only ever breaks on the physical-phone path.

## Frida must be 17.x

friTap 2.x requires Frida 17. If you are coming from older PiRogue-based tooling
pinned to Frida 16, that pin has to go: `Module.findExportByName` and
`Memory.readCString` no longer exist in 17, and `enumerateExports()` can return
entries with an undefined `name` — filter on it before calling `indexOf`.

## Android 14 emulator: perfetto crashes everything

On some Android 14 arm64 system images perfetto's heap profiling raises SIGSEGV and
takes the whole target process — sometimes Play Services too — down at launch:

```bash
adb -s <id> shell setprop persist.traced.enable 0
adb -s <id> reboot        # persist props only apply at boot
```

`setup-device.sh` sets the prop; the reboot is yours to do. If a target still dies
instantly on launch, check the related `heapprofd`/`traced_perf` properties — the
exact trigger varies by image.

## `adb exec-out` corrupts pcaps

Streaming `tcpdump` through `adb exec-out` mixes its stderr into the binary stdout.
The file starts with `tcpdump: data link type LINUX_SLL2` and then fails with
`pcap_loop: invalid packet capture length 1936288800` — that number is the ASCII
`sock`. Write to a file on the device and `adb pull` it.

## The web UI takes screenshots through the same corruptible channel

`adb exec-out screencap -p` has the problem above in miniature: a device whose
`screencap` writes anything to stderr produces a PNG with junk spliced into it,
and a header check will not notice — the file starts correctly and fails later,
in the decoder. The UI checks the terminating `IEND` chunk as well, and falls
back to writing on the device and pulling the file when that fails.

Related: `uiautomator dump` has no stable hierarchy to give while the screen is
animating, and returns an error rather than an empty screen. That is temporary
and normal; the UI says so instead of drawing an empty overlay, which would read
as "nothing here is clickable".

## The kernel completes a handshake with nobody's pid

`sock:inet_sock_set_state` looks like it hands you a connection with its owner
attached. It does, once. Captured on Linux 6.8, one `curl` to one host:

```
 <...>-2974095 [004] ..... inet_sock_set_state: ... sport=0     dport=443 daddr=104.20.23.154 oldstate=TCP_CLOSE     newstate=TCP_SYN_SENT
<idle>-0       [003] ..s2. inet_sock_set_state: ... sport=35032 dport=443 daddr=104.20.23.154 oldstate=TCP_SYN_SENT  newstate=TCP_ESTABLISHED
```

The connect is recorded against the calling task. The **handshake completing is
recorded against `<idle>-0`** — the SYN-ACK is processed in softirq context, and
ftrace attributes it to whatever the CPU was doing, which is nothing. Filter
`set_event_pid` down to the target's pids, as you must to avoid collecting the
whole device, and every destination is reported as *attempted* and none as
*established*.

The connect event also carries `sport=0` — the source port is not assigned yet —
so the two cannot be correlated by their source port either.

`set_event_pid` does accept `0`, which brings the handshakes back. That looked
like the fix until the same experiment ran on the Android 14 emulator, where the
`SYN_SENT→ESTABLISHED` event **never arrives at all**, with or without pid 0 in
the filter. What does arrive, on the socket's own task and so under any sane
filter, is every later transition *out of* `ESTABLISHED`:

```
nc-14965 [001] ..... inet_sock_set_state: ... oldstate=TCP_ESTABLISHED newstate=TCP_FIN_WAIT1
```

A socket cannot leave `ESTABLISHED` without having been there, so that is the
proof, it belongs to the right process, and it needs no device-wide collection.
sockstack reads establishment from it. The cost is stated in the artifact: a
connection still open when the run ends never leaves `ESTABLISHED`, so it is
reported as attempted.

## Polling flatters itself against root-owned traffic

Comparing the poller with the event stream, using a process owned by an ordinary
uid: eight destinations, one 0.3-second connection each. The stream saw 8, the
poll saw 1.

Run the same generator as root and the poll appears to catch 7 of 8 — which is
not the poller improving. A closed socket is orphaned and its `/proc/net` row is
attributed to **uid 0**, so root-owned traffic leaves an afterglow in the table
long after the process is gone, and a check filtering on uid 0 keeps finding it.
An app's uid has no such afterglow. Measure a sampling check against a real app's
uid, or the number it gives you is its own.

## `adb connect` exits 0 when it fails

```
$ adb connect 10.0.0.5:5555 ; echo $?
failed to connect to '10.0.0.5:5555': Connection refused
0
```

The exit status describes the command, not the connection. Anything reading it
adds a device that is not there, which is discovered one step later as a run that
traces nothing. Read the sentence: `connected to` / `already connected to` are the
only two outcomes that mean a device arrived.

## A version-mismatched adb client kills the server — including a forwarded one

`adb` kills any server whose protocol version differs from the client's and
starts its own. Forward a remote host's `5037` over SSH, point a differently
versioned client at it, and the thing it kills is the **remote** server, taking
every session on that host with it — the local client then quietly starts a local
daemon on the near end of the tunnel and reports no devices, which reads like a
network problem.

Match the two `adb --version`s before forwarding a server, or forward the device
port (`5555`) instead — that carries no client/server negotiation. Better still,
run the panel on the host with the device and forward the panel's own port; then
the only thing crossing the tunnel is HTTP.

## Root differs: emulator vs phone

- **Emulator / userdebug:** `adb root`, and the shell is already root.
- **Physical phone (Magisk):** root only through `su -c`.

sockstack detects which and wraps privileged commands accordingly. On a stock
phone you must also push a static `tcpdump` and a `frida-server` built for the
phone's ABI — `setup-device.sh` prints the device ABI, and a mismatch there is the
most common reason frida-server appears to start and then does nothing.

## Do not validate the tool on a hostile sample

Frida spawn-gating is not reliable for every app. Some samples fail to launch under
spawn in one run out of two and degrade further with each attempt — and this hits
friTap's own CLI just as hard, so it is not a sockstack bug and there is nothing
to fix in your setup. Chasing it while also debugging your own plumbing wastes
hours and teaches you nothing.

Bring the toolchain up against something cooperative first — `--host` against `curl`
needs no device at all — and only then point it at the sample. If a sample will not
spawn, `--attach` to it after starting it by hand, accepting that you miss whatever
it did before you attached.

## An app on a splash screen makes no requests

Drive the app while the collection window is open (`adb shell input tap …`, or by
hand), otherwise there is nothing to intercept. If a run comes back empty, check
`socket_trace_meta.json` first — it distinguishes "the tracer never installed" from
"the app was quiet" — then check that the app started at all, and that its launcher
activity is what you think it is; it is frequently *not* `MainActivity`:

```bash
adb shell cmd package resolve-activity --brief <pkg>
```
