# Changelog

## Unreleased

### Added — `--ftrace`, a kernel event stream beside the poller (prototype)

The `/proc/net` cross-check samples every two seconds, so a connection that
opens and closes between two polls is missed by it and by everything else. This
subscribes to `sock:inet_sock_set_state` in a tracing instance of its own and
reads the events as they happen. Root is the only requirement — no eBPF
toolchain, no BTF, no compiler, nothing pushed to the device.

It is a second source for *what happened*, not for *who did it*. The kernel
knows pid, comm and uid; it does not know `com.target.SyncWorker.run`, and no
kernel-side source ever will. Attribution stays where it is.

TCP only, and the artifact says so, because UDP has no state machine to observe
and silence here would otherwise read as "no datagrams were sent".

Both kernel sources merge into one `uid_sockets.json`, each destination carrying
which source saw it, and the summary reports how many destinations polling
missed. That number is the point of the prototype: it says whether the gap is
worth closing with something heavier.

Found while building it, on a live kernel rather than from documentation: the
connect transition is recorded against the calling task, but the handshake
completing is recorded against `<idle>-0`, in softirq context. A pid filter — the
only thing keeping this from collecting the whole device — therefore hides every
successful connection and leaves nothing but attempts. `set_event_pid` accepts
`0`, which brings the handshakes back device-wide, so they are used only to
upgrade destinations one of the target's own pids was already seen dialling. The
imprecision that leaves is stated in the artifact: a concurrent connection to the
same address and port can lend its handshake to the target's, promoting
"attempted" to "established" — it cannot invent a destination. `docs/GOTCHAS.md`
carries the capture this came from.

**Not yet run against a device.** The parser is tested against verbatim kernel
output; the plumbing around it — tracefs discovery under SELinux, the pid filter,
the teardown — has not been exercised on Android.

### Added — an optional web front-end (`ui/`)

Reworked to a hi-fi design: a launch screen that picks the device, and a
"cockpit" workspace where the device mirror sits beside the findings and the log
runs along the bottom. Attribution gets the room, because attribution is the
product.

The findings panel is built by calling sockstack's own `summarize_trace`, not by
re-deriving anything — there is no second implementation to drift from the
written report. Peer colour encodes **how well the tool knows who opened the
socket**: green when the stack names application code, neutral for library-only
and native threads, amber for anything unexamined or where the Java bridge was
unavailable. It deliberately does not encode suspicion. The tool cannot tell a
C2 from a CDN, and a red badge claiming otherwise would be the confident wrong
answer this project spends its effort removing; a test asserts the vocabulary
contains no verdict words at all.

For the same reason recent runs are described by what they recorded — call
sites, records, whether the bridge worked — and never as "clean". Nothing found
and nothing working look identical from the outside.

For a device on a host reached with an SSH key, the card prints the three tunnel
recipes with the host filled in and states which adb server it is talking to, so
the forwarded-server form can be seen to have worked. It does not run `ssh`: the
page has no login of its own, and a button that used your key would be lending it
to whoever opened the page. `docs/GOTCHAS.md` gains the trap that makes the
forwarded-server form bite — a version-mismatched client kills the server it
connects to, which over a tunnel is the remote one.

A stand reached over the network can be connected from the page: an address, a
button, `adb connect` underneath, and pairing for Android 11+ wireless debugging
behind a link since its port and code are different and change every time. The
result is read from what adb says, not from how it exited — `adb connect` exits 0
while printing "failed to connect to…", and believing the exit status would put a
device in the list that is not there, which is discovered later as a run against
nothing. Network devices carry a disconnect; USB ones do not.

Getting the APK onto the device is now a step of the launch screen instead of a
field below a phone-sized frame nobody scrolled past. It takes a drop or a file
picker as well as a path, because the browser is usually not on the machine
holding the device — a laptop tunnelled into the stand — and a path field only
ever worked for files that were already there. Uploads land in a temp directory
on the adb host with the filename reduced to a basename that cannot climb out of
it, and a transfer that ends early is deleted and reported as a short transfer,
not left to install as a parse error that reads like a broken sample.

The interface speaks English and Russian, switched from the top bar and
remembered. Only the interface: adb output, sockstack's log and the findings text
stay in the words the tool produced them in. Both string tables are checked
against each other and against every key the page asks for, because a missing key
does not fail — it renders its own name where a sentence should be.

Fonts are the system stack rather than a webfont CDN: a forensic console should
not phone home when a page opens, and on an isolated host it would not render.

Standard library only, so the CLI gains no dependencies and anyone uninterested
in a browser loses nothing. It runs the same `sockstack.py` commands into the
same output directories; nothing it does is unavailable without it.

The reason it is worth having is not the form fields. Driving a target from a
terminal means `input tap 797 1284`, with the coordinates obtained by dumping the
view hierarchy, parsing XML and computing a centre by hand — slow, and wrong
often enough to cost a run. The page renders the device's screen with every
clickable element outlined by its resource id, so a tap is a click on
`installUpdateBtn` rather than an aim at a point. Verified against a live dropper:
both buttons found, centres matching the ones previously worked out by hand.

Also: device list (including devices present but unauthorized, rather than an
empty list), package list newest-install first with the UID, APK install that
reports the package name it registered under, launch, back/home, and the run log
streamed while it happens.

No authentication, and it controls the device — it binds to loopback, and says
what `--bind` costs.


## 2.3.1

Review of 2.3.0 found that the safety net added there could itself go quietly
wrong, in the ways it was built to prevent. Nine fixes, all in that feature.

### Fixed — the cross-check could cost the whole capture

`uid_sockets.json` was written from a set a live poller thread might still be
mutating, and it was written *before* `cleanup_device()`, which is what pulls
`traffic.pcap` off the device. `join(5)` is not a guarantee: the poller blocks in
an `adb` call with a 60-second timeout, and a wedged device — which this codebase
assumes as normal everywhere else — leaves it running well past the join. The
iteration would then raise, and with no `try` anywhere downstream that would skip
the counts, the metadata, **the capture pull**, the session stop, the summary and
the manifest. An optional cross-check had been placed ahead of the evidence.

The poller now snapshots under a lock, and its artifact is written after the
capture is safely off the device, inside a `try`.

### Fixed — the report's own legend described the previous release

2.3.0 made `target` mean "seen by the tracer **or** the kernel", updated the
README and the walkthrough, and left the paragraph the report itself prints
saying the tracer alone. That paragraph had been rewritten one commit earlier
for exactly this reason. It now matches the code, and the `other process` mark —
the last positive claim left about traffic nobody observed — reads `not
attributed`.

### Fixed — UDP was not polled, though the tracer records it

The cross-check read `/proc/net/tcp` and `tcp6` only, making the safety net
narrower than the thing it guards. It also missed the motivating case: Go
resolves DNS over a connected UDP socket, so a Go payload's own lookups were
invisible to both views while the status line reported agreement. All four
tables are read now, and each destination carries the protocol it was seen on.

### Fixed — "agreement" was reported as if it meant attribution

The comparison uses every tracer record regardless of whether a stack was
captured, so a run with a broken Java bridge — no attribution at all — still
reported full agreement, under wording that told the reader attribution covered
the traffic. The line now says `N with no tracer record`, which is a claim about
observed sockets, and the walkthrough says plainly that it is not a claim about
call stacks.

### Fixed — a check that never ran looked exactly like one that found nothing

Four situations produced an identical report: `--host`, an unresolved UID, a run
cut short, and a directory from before the feature existed. The artifact is now
always written on a device run and carries its own status, so the report can
distinguish *did not run*, *could not read `/proc/net`*, and *ran and agreed*.
Poll successes and failures are counted.

### Fixed — the cross-check switched itself off under `--attach`

`resolve_uid` looked the package up in the package manager. But attaching names
a process the way Frida does — by label, `Chrome` rather than
`com.android.chrome` — which matches no package, so the check silently did
nothing in the mode documented for samples with no launcher activity: most RATs.
It now falls back to the UID of the process the tracer is actually in.

### Fixed — shared UIDs were assumed not to exist

`android:sharedUserId` still does, and `android.uid.system` is UID 1000 — on the
test emulator five packages share one application-range UID. The check cannot
tell those packages' sockets apart, so it now reports which packages share the
UID instead of quietly attributing their traffic to the target.

### Fixed — the section named one cause and there are several

"Traffic the tracer has no record of" asserted raw syscalls. A socket already
open and idle when instrumentation attached leaves identical evidence, as does a
run that lost its counts artifact, and a row still in `SYN_SENT` is a connection
*attempted* — what a dead C2 being retried looks like. The section now lists the
candidates instead of choosing one, and unestablished connections are marked.

### Fixed — the comparison dropped the port it had collected

Matching on address alone hid a second channel to a host the tracer already knew:
a payload reusing the app's own CDN address on another port. Both sides carry
ports; both are now compared.

### Fixed — a test fixture claimed a provenance it did not have

The `/proc/net/tcp6` fixture was labelled as captured from a device, but its
remote address had been hand-edited and decoded to a different host than the
device produced. In a suite where comments cite real runs, one that does not
devalues the rest. The verbatim row is restored and the added rows are marked as
added.


## 2.3.0

### Added — a kernel cross-check, so a blind spot cannot pass for someone else's traffic

The tracer hooks libc. A payload that issues raw syscalls — a Go runtime, a
statically linked binary — never goes through it, so there is no record to make
and nothing to attribute. That much was already documented. What was not
acknowledged is the consequence: the traffic still lands in the device-wide
capture, nothing ties it to the target, and the summary then printed it in the
lower sections as another process's. The one part of the report whose job is to
separate the sample's traffic from its neighbours' was giving a confident wrong
answer in exactly the case where it mattered most.

The kernel does not have this blind spot. Every socket in `/proc/net/tcp` carries
the UID that owns it, and Android gives each package its own. Each device run now
polls that table for the target's UID and writes `uid_sockets.json`. The result
feeds the report twice: those destinations count as the target's when marking DNS,
SNI and HTTP entries, and any of them the tracer never saw are listed under
**Traffic the tracer never saw** — the target's connections, honestly labelled as
un-attributable rather than misfiled.

This narrows the gap; it does not close it. Polling samples every two seconds, so
a connection opened and closed in between is missed by both views, and the check
can name a blind spot but never attribute one. Run status carries the count either
way, including `0 unseen`, so agreement is stated rather than assumed.


## 2.2.2

### Added — `docs/USAGE.md`

A walkthrough from an empty directory to an attributed report, with the real
output of every step. It exists because the README lists what the commands are
and not what a healthy run looks like: several lines that read as failures
(`friTap did not stop within 30s`, `not hooked (absent from this libc)`,
`decryption: not attempted`) are normal and expected, and a reader with no way
to tell those from real breakage will either stop at the first one or ignore all
of them. It also covers reading the report section by section, what each
unattributed reason licenses you to conclude, and what the tool will not tell
you.

### Fixed — disambiguation gave up after one frame

2.2.1 made colliding entries reach deeper for a frame that tells them apart, but
it extended the display once and considered the group handled. A group of two
always splits on the first differing frame; a group of three or more usually
does not. The first differing depth separates one member and leaves the rest
identical to each other, and those were still printed as the same line.

Found by running the tool against F-Droid, whose okhttp reader enters the
library at the same frame from several places: `readConnectionPreface` and the
frame-reading loop both sit under `RealBufferedSource.request` and diverge five
frames further down, and two writes shared `Http2Writer.flush` while one was
sending request headers and the other finishing the request body. Four of twelve
call sites in that report were two pairs of identical-looking lines.

Disambiguation now repeats — regrouping on what is currently displayed and
extending again — until every entry renders differently or the stacks run out of
frames to distinguish them. A per-item cursor tracks how deep the display has
reached, since the frame appended at depth 7 is the fourth one shown.

### Fixed — provisioning could not tell a working frida-server from a useless one

`setup-device.sh` pushed the binary, chmod'd it, and declared success. A
frida-server built for the wrong architecture pushes and chmods exactly like a
correct one, so the failure surfaced much later, inside a run, as a
twenty-second wait and `could not bring frida-server up` — a message that named
neither the cause nor the fix.

The script now starts what it pushed and waits for it, so the failure lands at
provisioning time, next to the binary in question, and says which ABI the device
reports against which file was pushed. It also refuses to report success when
there is no frida-server on the device at all and none was supplied.

Both here and in the runner, the suggested download now names the architecture
the way Frida's releases do: a device reporting `arm64-v8a` needs
`…-android-arm64`, and echoing the ABI back pointed at a file that never
existed.

## 2.2.1

### Fixed — the runner and the agent disagreed on what "the same call site" is

Two deduplication passes with different keys. The agent's signature covers every
non-framework frame; the runner rebuilt its own key from the *classified* frames
— the application frames plus only the **first** library frame. Two call sites
that shared their application frames and diverged deeper inside okhttp were two
records to the agent and one line in the report.

The effect was an undercount of the one number this tool exists to produce.
Re-running the malware capture from 2.2.0 through the fixed code turns 8
attribution lines into 11, and the sample's C2 from six distinct call sites into
**seven** — a whole code path that reached a command-and-control server was
being dropped from the report.

There is now one definition of call-site identity and it belongs to the side
that captured the stack: the agent emits `stack_signature` with every record and
the runner deduplicates on it. Artifacts captured before this release fall back
to comparing the full frame lists rather than the first library frame.

### Fixed — distinct call sites could print identically

Deduplicating correctly is not enough if the report renders two findings as the
same line: a reader discards one as a glitch. When entries collide visually the
summary now reaches deeper — into the application frames past the three normally
shown, or further down the library chain — for the first frame that differs. In
the malware run this is what separates two paths sharing `ca0.j:96 → ca0.e:12 →
wf1.H:7` and diverging only on the fourth frame.

Neither defect could have been caught by the existing tests: they compared call
sites with *different* application frames, which worked either way. Three tests
now cover the cases that failed.

## 2.2.0

The theme of this release is that the tool must not state more than it knows.
Two defects, both found by review rather than by a failing test, made it report
confident wrong answers about the one thing it exists to answer.

### Fixed — the summary called unexamined destinations "native code"

The agent recorded *why* each record had no Java stack; the summary ignored that
and decided from the absence of frames alone. Records nobody stack-walked,
records from a thread with no JVM, and records whose walk threw all looked
identical to it, and all were printed under "native code — Cronet, JNI, or a
non-JVM runtime".

In a run against live malware the same C2 address appeared **under call-stack
attribution and under "native code" in the same report**, because one operation
to it was attributed and another had been skipped.

The reporting layer now reads `stack_source`, groups unattributed peers by
reason, and never describes anything but `native-thread` as native. When a
peer's records disagree, the reason conceding the most ignorance wins; an
unrecognised value ranks as *less* certain than "native", so a future agent
state can never be silently read as one. A peer that is attributed anywhere no
longer appears in any unattributed list — if some of its operations were
skipped, it is listed as attributed but not exhaustively examined.

### Fixed — distinct call sites to one host were silently discarded

Call-site signatures hashed the first eight stack frames. Java stacks arrive
innermost-first, so those eight are always the same `libcore`/`java.net`
plumbing: every caller reaching a host through `java.net.Socket` produced an
identical signature and the deduplicator dropped all but the first. Signatures
are now computed from the frames that can actually discriminate.

### Fixed — the stack-walk budget was spent on duplicates

The per-destination budget was charged for every walk, including walks whose
result was immediately discarded as a duplicate. Eight credits on one C2 yielded
two distinct call sites and six discarded repeats, after which genuinely
different callers were marked "not walked". The budget now counts *distinct call
sites kept* (8 per destination) with a separate ceiling on walks performed (48),
so a hot destination still cannot cost unbounded work.

### Added

- `stack-error` — a stack walk that throws is now counted, warned about in the
  summary, and reported as attribution-unavailable rather than as native.
- `run_manifest.json` records `tracer_script_sha256`. The agent is a build
  artifact whose behaviour changes without its name changing; the path alone
  could not tie a finding to the code that produced it.
- `tests/test_bundle_fresh.py` rebuilds the agent and fails if the shipped
  bundle no longer matches `agent/src/`.
- On `ProcessNotFound` when attaching, the candidate process names Frida
  actually knows are printed. Frida names a foreground app's main process by its
  label, so `--package com.android.chrome` fails while the app is visibly
  running and the answer is `--package Chrome`.
- `stack_source` is documented, with a table of every value and how it is
  reported.

### Changed

- Rerunning into an existing output directory now **moves** the previous run's
  artifacts into `previous_run_<timestamp>/` instead of deleting them. Captures
  and keylogs are frequently not reproducible, so losing them must not be the
  default.
- `socket_trace_meta.json` merges tracer messages instead of letting whichever
  arrived last overwrite the others, and carries a `warnings` list.
- **friTap's root evasion is now off by default in every mode.** It was off only
  for `--attach`, on the assumption that attaching was what triggered its crash
  on Android 14. That assumption was wrong: the crash reproduces identically on
  spawn, on a fresh x86_64 emulator, against an ordinary app. A default that
  reliably stops the tool from starting is not a useful default. `--anti-root`
  turns it on for the one case that needs it — a sample that genuinely refuses
  to run under root — and that case still hits the friTap crash.

### Licensing

`NOTICE` now records the packages that `frida-compile` inlines into the shipped
bundle and therefore redistributes: `frida-java-bridge` (LGPL-2.0 WITH
WxWindows-exception-3.1), `buffer` and `base64-js` (MIT), `ieee754`
(BSD-3-Clause). The previous NOTICE attributed a file that no longer exists.

## 2.1.0

Frida 17 removed the built-in `Java` global. The tracer's guard
(`if (typeof Java === 'undefined') return null;`) meant it kept running, hooked
everything and labelled every record "native" — a full detonation against real
malware produced 33 records, none attributed, and the run looked healthy.

The agent became a compiled artifact with `frida-java-bridge` bundled in, and
the absence of a working bridge became a reported error instead of a silent
"native".
