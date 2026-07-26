# Changelog

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
