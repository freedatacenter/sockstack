# Frida instrumentation

`socket_trace.bundle.js` is a **build artifact** — do not edit it. The source
lives in [`../../agent/src/`](../../agent/src/) and is compiled with
`frida-compile`:

```bash
cd agent && npm ci && npm run build
```

The build is byte-for-byte reproducible, and `tests/test_bundle_fresh.py` fails
if this file no longer matches `agent/src/` — an edit that was never rebuilt
would otherwise leave the tracer running the old behaviour while the sources
describe the new one.

It is a bundle rather than a plain script because Frida 17 removed the built-in
`Java` global; `frida-java-bridge` has to be compiled in, or call-stack
attribution silently disappears (see `../../docs/GOTCHAS.md`).

Everything else droidtrace needs — TLS keylogging, pinning bypass, root evasion,
spawn/attach — comes from [friTap](https://github.com/fkie-cad/friTap) and is not
duplicated here.

The agent is loaded by droidtrace as a friTap `ScriptPlugin` and speaks over
`send()`:

| message | meaning |
|---|---|
| `socket_trace_ready` | hooks installed, libc name, Java-bridge state |
| `socket_trace_log` | one socket operation, its peer and its call stack |
| `socket_trace_counts` | per-peer totals; also the runner's liveness signal |
| `socket_trace_error` | the tracer could not install, or the Java bridge is missing |
| `socket_trace_warning` | the tracer runs, but something degrades the result — a stack walk that threw |

Each record carries a `stack_source` saying how its stack was obtained, or why it
has none. The runner turns those values into the summary's verdict and never
reports any of them except `native-thread` as native code; the table is in the
main [README](../../README.md#stack_source-why-a-record-has-the-stack-it-has).

Address parsing is unit-tested without Frida or a device:

```bash
node ../../tests/test_agent_addr.mjs
```

The approach and the original implementation come from the PiRogue Tool Suite
(AGPL-3.0); this is a substantially rewritten derivative. See `../../NOTICE`.
