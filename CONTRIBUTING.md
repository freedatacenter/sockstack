# Contributing

Thanks for looking. sockstack is maintained by one person, so the honest
expectation is: issues get read, replies may take days, and a small pull request
with a test lands far faster than a large one without.

## The one rule that matters

**This tool must never claim to know something it does not.**

Everything else here follows from that. An analyst reads a report and decides
whether an app is hostile; a confident sentence about a socket nobody watched is
worse than no sentence at all. So:

- "We did not look" and "there was nothing to see" are different findings, and
  the code keeps them apart on purpose — see `stack_source` in the README.
- Silence is never evidence. If a check could not run, the output says so and
  says what its absence does *not* prove.
- When something cannot be attributed, the tool reports it as unattributed
  rather than guessing an owner.

A change that makes the tool sound more decisive by dropping one of these
distinctions will be turned down even if it is otherwise good code.

## Running the tests

No device and no Frida needed:

```bash
python3 -m unittest discover -s tests -v
node --test tests/test_agent_addr.mjs
```

One test rebuilds the Frida agent and compares it byte-for-byte with the bundle
committed to the tree. It **skips** when the toolchain is absent, and a skip
means the check did not run — not that the bundle is current. If you touched
anything under `agent/src/`:

```bash
cd agent && npm ci && npm run build
```

and commit the rebuilt `scripts/frida/socket_trace.bundle.js` with your change.
The bundle ships in the tree so users need no Node; the cost is that it can go
stale, and a stale bundle means the tracer runs code the sources no longer
describe while every finding is attributed to the code you can read.

## What a good change looks like

**Tests that describe a failure, not a function.** The suite is written so each
test names the thing that went wrong once. `test_a_worker_threads_event_is_not_
thrown_away` is more useful in six months than `test_note_returns_true`. If you
are fixing a bug, the test should fail before your fix for the reason the bug
existed.

**Comments that say why.** What the code does is visible; why it does it that
way, and what happened when it did something else, is not. Prefer a sentence of
history to a paraphrase of the next line.

**Anything that cost you an afternoon goes in [`docs/GOTCHAS.md`](docs/GOTCHAS.md).**
That file is the most valuable one here. If a trap bit you, it will bite the
next person.

**Claims need backing.** A statement added to the README or a report should be
supported by a test or by a measured run whose numbers you quote. "It catches
short-lived connections" is a hope; "19 events, 4 destinations the 2-second poll
missed, measured against a live app" is a claim.

## Things that need a device

Most of the suite runs anywhere, but attribution cannot be regression-tested
without a real Java runtime. If your change touches the agent, the kernel
sources, or anything that talks to `adb`, please run it against a real app and
say so in the pull request — what you ran, for how long, and what came out.

`./scripts/preflight.sh --device <serial> --package <pkg>` checks a host and a
device end to end and finishes with a real short run.

## Reporting a bug

Useful reports include:

- what you ran, in full;
- the `## Run status` section of `summary_*.md` — it distinguishes "the tracer
  never installed" from "the app was quiet";
- versions: Frida on the host and on the device, friTap, Android release and ABI.

**Please redact before you paste.** A run directory holds TLS session keys and
decrypted traffic, and an issue is public. Replace real hostnames, addresses and
tokens with placeholders; the shape of the output is what we need, not the
indicators. Do not attach `sslkeylog.txt`, a pcap, or a decrypted body — ever.

## Scope

sockstack answers one question: which code path opened this socket. It is a
plugin on friTap's public API, and it does not fork or vendor it. TLS
interception, pinning bypass and device handling belong upstream in
[friTap](https://github.com/fkie-cad/friTap); a fix there helps more people than
a workaround here.

## Commits

Write the message for someone who arrives in a year with a bisect and a
question. Say what was wrong and why the fix is shaped the way it is; the diff
already says what changed. Subject in the imperative, wrapped at 72 columns, and
one concern per commit.

## Licence

By contributing you agree your work is released under **AGPL-3.0**, the licence
of this project — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE) for the
attribution this code carries.
