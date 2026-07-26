/*
 * socket_trace — socket operations with Java call-stack attribution.
 *
 * Records, for every socket operation an app performs, the peer address and the
 * Java stack that produced it. That mapping — "this host was contacted from
 * this code path" — is what friTap does not provide and this plugin adds.
 *
 * ---------------------------------------------------------------------------
 * Origin and licence
 *
 * The approach and the original implementation come from the PiRogue Tool Suite
 * (pirogue-cli), Defensive Lab Agency, licensed AGPL-3.0:
 *     https://github.com/PiRogueToolSuite/pirogue-cli
 * This is a substantially rewritten derivative and remains AGPL-3.0.
 *
 * Rewritten by Free Data Center (2026). What changed and why:
 *
 *  - Frida 17 removed the built-in `Java` global; the bridge is an npm package
 *    that has to be bundled. Without it the tracer silently reports every
 *    record as native and the whole feature disappears without an error. The
 *    bridge is imported here and its absence is reported loudly, not guessed at.
 *  - Export names are matched EXACTLY. The original prefix match caught
 *    readahead/readv/pwrite64/sendfile and hooked far more than intended.
 *  - Descriptors learned at connect/sendto time are cached; every other hook
 *    consults the cache before any socket query. `Socket.type()` per syscall is
 *    what makes a tracer kill its target.
 *  - Addresses come from the syscall arguments wherever the kernel puts them
 *    there: connect (args[1]), sendto (args[4]), sendmsg (msghdr.msg_name), and
 *    recvfrom/recvmsg on RETURN. `Socket.peerAddress()` only answers for
 *    connected sockets, so relying on it drops unconnected UDP entirely — DNS,
 *    QUIC and HTTP/3.
 *  - close()/dup2() evict the descriptor, because a recycled fd would otherwise
 *    keep reporting the previous socket's peer — a confident, plausible, WRONG
 *    attribution.
 *  - Stack walking is budgeted per destination by the number of DISTINCT call
 *    sites captured, so repeats of one caller cannot exhaust the allowance and
 *    hide the others, while a separate ceiling keeps the cost bounded.
 *  - Every record says how its stack was obtained, or why it has none. "We did
 *    not look" and "there was nothing to see" are different findings and are
 *    never merged.
 * ---------------------------------------------------------------------------
 */
import Java from 'frida-java-bridge';
import { parseSockaddr, hashFrames } from './addr.js';

const IS_DARWIN = Process.platform === 'darwin';
const LIBC_CANDIDATES = {
    linux: ['libc.so', 'libc.so.6'],
    darwin: ['libSystem.B.dylib']
}[Process.platform] || ['libc.so'];

const MAX_EVENTS = 500;
// Distinct call sites worth keeping per destination — the useful budget.
const MAX_STACKS_PER_DEST = 8;
// Hard ceiling on expensive walks per destination. A single call site hammering
// one host must not cost an unbounded number of getStackTrace() calls; that is
// how instrumentation kills its target.
const MAX_WALKS_PER_DEST = 48;
const COUNTS_INTERVAL_MS = 2000;
const POINTER_SIZE = Process.pointerSize;

// Hook groups. The value is the index of the sockaddr pointer in the arguments.
const SOCKADDR_ON_ENTER = { connect: 1, sendto: 4 };   // supplied by the caller
const SOCKADDR_ON_LEAVE = { recvfrom: 4 };             // filled by the kernel
const MSGHDR_ON_ENTER = ['sendmsg'];
const MSGHDR_ON_LEAVE = ['recvmsg'];
const PEER_HOOKS = ['send', 'recv'];                   // connected sockets only
const FD_HOOKS = ['read', 'write', '__read_chk', '__write_chk'];
const CLOSE_HOOKS = ['close'];
const DUP_HOOKS = ['dup2', 'dup3'];

const sockFds = {};   // fd -> {ip, port}
const counts = {};    // "op|ip|port" -> total operations, never capped
const sigSeen = {};   // "op|ip|port|signature" -> true
const walks = {};     // "op|ip|port" -> expensive stack walks performed
const kept = {};      // "op|ip|port" -> distinct call sites recorded
let emitted = 0;
let truncated = false;
let ExceptionClass = null;
let stackErrors = 0;
let stackErrorSample = null;

// ---------------------------------------------------------------- java bridge

/* Does this process have a Java runtime at all? Checked against the loaded
 * modules rather than inferred, so "no Java here" and "the bridge failed to
 * load" stay distinguishable — conflating them is exactly how a broken bridge
 * hid behind 33 records of plausible-looking "native". */
function hasAndroidRuntime() {
    try {
        return Process.enumerateModules().some(m => /^libart\.so$|^libdvm\.so$/.test(m.name));
    } catch (e) {
        return false;
    }
}

let bridgeReady = false;
let bridgeError = null;
try {
    bridgeReady = Java.available === true;
} catch (e) {
    bridgeError = 'frida-java-bridge threw: ' + (e && e.message ? e.message : e);
}
/* A working bridge is itself proof of a runtime. Deciding on the module list
 * alone would misfile a process whose ART ships under a vendor soname as
 * "no Java runtime at all" — turning real attribution into a claim that the
 * process has no Java in it. Odd sonames are exactly what odd phones have, and
 * odd phones are where the interesting samples run. */
const runtimePresent = hasAndroidRuntime() || bridgeReady;
if (!bridgeReady && runtimePresent) {
    bridgeError = bridgeError || 'frida-java-bridge loaded but Java.available is false';
}

/* Returns [frames|null, source]. `source` separates the outcomes the report must
 * never merge: a real Java stack, a thread with no JVM attached, a bridge that
 * never loaded, a process with no Java at all, and a walk that threw. Only the
 * second of those means "this call site is native code". */
function javaStack() {
    if (!bridgeReady) return [null, runtimePresent ? 'no-bridge' : 'no-runtime'];
    try {
        if (Java.vm === null || Java.vm.tryGetEnv() === null) return [null, 'native-thread'];
        if (ExceptionClass === null) ExceptionClass = Java.use('java.lang.Exception');
        const frames = ExceptionClass.$new().getStackTrace().map(frame => ({
            class: frame.getClassName(),
            file: frame.getFileName(),
            line: frame.getLineNumber(),
            method: frame.getMethodName(),
            is_native: frame.isNativeMethod(),
            str: frame.toString()
        }));
        return [frames, 'java'];
    } catch (e) {
        // Counted and reported: a bridge that loads and then throws on every walk
        // would otherwise produce a run full of unattributed records with nothing
        // anywhere saying why.
        stackErrors += 1;
        if (stackErrorSample === null) {
            stackErrorSample = (e && e.message ? e.message : String(e));
            send({
                type: 'socket_trace_warning', dump: 'socket_trace_meta.json',
                data_type: 'json',
                data: { warning: 'java stack walk threw: ' + stackErrorSample +
                                 ' — affected records are marked stack-error, not native' }
            });
        }
        return [null, 'stack-error'];
    }
}

// ---------------------------------------------------------------- addresses

/* struct msghdr { void *msg_name; socklen_t msg_namelen; ... }
 *
 * Assumes an LP64 little-endian ABI: msg_name is a pointer, msg_namelen is a
 * 4-byte socklen_t immediately after it. True for Android arm64 and x86_64,
 * and the first two fields are laid out the same way on the BSD/darwin struct,
 * which is why --host works there. It would need revisiting for a 32-bit or
 * big-endian target; the sockaddr parser is explicit about darwin's sa_len, so
 * be equally explicit here. */
function parseMsghdr(ptr_) {
    try {
        if (ptr_ === null || ptr_.isNull()) return null;
        const name = ptr_.readPointer();
        if (name.isNull()) return null;
        if (ptr_.add(POINTER_SIZE).readU32() === 0) return null;   // msg_namelen
        return parseSockaddr(name, IS_DARWIN);
    } catch (e) {
        return null;
    }
}

function peerOf(fd) {
    try {
        const type = Socket.type(fd);
        if (type !== 'tcp' && type !== 'tcp6' && type !== 'udp' && type !== 'udp6') return null;
        const peer = Socket.peerAddress(fd);
        return peer ? { ip: peer.ip, port: peer.port } : null;
    } catch (e) {
        return null;
    }
}

// ---------------------------------------------------------------- emit

function sendCounts() {
    send({
        type: 'socket_trace_counts',
        dump: 'socket_trace_counts.json',
        data_type: 'json',
        data: { counts, emitted, truncated, max_events: MAX_EVENTS,
                stack_errors: stackErrors, stack_error_sample: stackErrorSample }
    });
}

function emit(fd, operation, peer, threadId) {
    if (!peer) return;
    const destKey = `${operation}|${peer.ip}|${peer.port}`;
    // Counted before any cap, so a destination first seen past the cap is still
    // visible as a number even when its record is not stored.
    counts[destKey] = (counts[destKey] || 0) + 1;
    if (emitted >= MAX_EVENTS) {
        if (!truncated) { truncated = true; sendCounts(); }
        return;
    }

    let frames = null;
    let source = bridgeReady ? 'not-walked' : (runtimePresent ? 'no-bridge' : 'no-runtime');
    // Budget is spent on *captured stacks*, not on attempts. Charging every
    // attempt burned the whole allowance on repeats of one call site, so later
    // and genuinely different callers to the same host were never examined —
    // and then got reported as if they had no Java stack at all.
    const walked = walks[destKey] || 0;
    if ((kept[destKey] || 0) < MAX_STACKS_PER_DEST && walked < MAX_WALKS_PER_DEST) {
        [frames, source] = javaStack();
        if (frames) walks[destKey] = walked + 1;
    }

    // Records with no stack are deduplicated per thread *and* per reason: two
    // different reasons for having no stack are two different findings.
    const signature = frames
        ? 's' + hashFrames(frames.map(f => f.str))
        : `t${threadId}|${source}`;
    const sigKey = `${destKey}|${signature}`;
    if (sigSeen[sigKey]) return;
    sigSeen[sigKey] = true;
    if (frames) kept[destKey] = (kept[destKey] || 0) + 1;
    emitted += 1;

    send({
        type: 'socket_trace_log',
        dump: 'socket_trace.json',
        data_type: 'json',
        timestamp: Date.now(),
        data: {
            socket_fd: fd,
            socket_event_type: operation,
            pid: Process.id,
            thread_id: threadId,
            peer_ip: peer.ip,
            peer_port: peer.port,
            stack_source: source,
            // The identity of this call site, as decided here. The runner
            // deduplicates on it rather than rebuilding its own key: two
            // definitions of "the same call site" in one pipeline drift apart
            // and silently change the one number this tool exists to report.
            stack_signature: signature,
            stack: frames
        }
    });
}

function learn(fd, peer) {
    if (peer) sockFds[fd] = peer;
    return peer;
}

// ---------------------------------------------------------------- hooks

let libc = null, libcName = null;
for (const candidate of LIBC_CANDIDATES) {
    if (libc !== null) break;
    try {
        libc = Process.getModuleByName(candidate);
        libcName = candidate;
    } catch (e) { /* try the next candidate */ }
}

if (libc === null) {
    send({
        type: 'socket_trace_error', dump: 'socket_trace_meta.json', data_type: 'json',
        data: { error: 'libc not found', tried: LIBC_CANDIDATES }
    });
} else {
    installHooks();
}

function handlerFor(name) {
    if (Object.prototype.hasOwnProperty.call(SOCKADDR_ON_ENTER, name)) {
        const argIndex = SOCKADDR_ON_ENTER[name];
        return {
            onEnter(args) {
                const fd = args[0].toInt32();
                if (fd < 0) return;
                let peer = parseSockaddr(args[argIndex], IS_DARWIN);
                if (!peer) peer = sockFds[fd] || peerOf(fd);      // connected sendto()
                emit(fd, name, learn(fd, peer), this.threadId);
            }
        };
    }
    if (Object.prototype.hasOwnProperty.call(SOCKADDR_ON_LEAVE, name)) {
        const leaveIndex = SOCKADDR_ON_LEAVE[name];
        return {
            onEnter(args) {
                this.dtFd = args[0].toInt32();
                this.dtAddr = args[leaveIndex];
                this.dtTid = this.threadId;
            },
            onLeave(retval) {
                if (this.dtFd === undefined || this.dtFd < 0 || retval.toInt32() < 0) return;
                let peer = parseSockaddr(this.dtAddr, IS_DARWIN);
                if (!peer) peer = sockFds[this.dtFd] || peerOf(this.dtFd);
                emit(this.dtFd, name, learn(this.dtFd, peer), this.dtTid);
            }
        };
    }
    if (MSGHDR_ON_ENTER.includes(name)) {
        return {
            onEnter(args) {
                const fd = args[0].toInt32();
                if (fd < 0) return;
                let peer = parseMsghdr(args[1]);
                if (!peer) peer = sockFds[fd] || peerOf(fd);
                emit(fd, name, learn(fd, peer), this.threadId);
            }
        };
    }
    if (MSGHDR_ON_LEAVE.includes(name)) {
        return {
            onEnter(args) {
                this.dtFd = args[0].toInt32();
                this.dtMsg = args[1];
                this.dtTid = this.threadId;
            },
            onLeave(retval) {
                if (this.dtFd === undefined || this.dtFd < 0 || retval.toInt32() < 0) return;
                let peer = parseMsghdr(this.dtMsg);
                if (!peer) peer = sockFds[this.dtFd] || peerOf(this.dtFd);
                emit(this.dtFd, name, learn(this.dtFd, peer), this.dtTid);
            }
        };
    }
    if (PEER_HOOKS.includes(name)) {
        return {
            onEnter(args) {
                const fd = args[0].toInt32();
                if (fd < 0) return;
                // Cache first: Socket.type()/peerAddress() on every send and recv
                // is precisely what makes a tracer unusable.
                let peer = sockFds[fd];
                if (peer === undefined) peer = learn(fd, peerOf(fd));
                emit(fd, name, peer, this.threadId);
            }
        };
    }
    if (FD_HOOKS.includes(name)) {
        return {
            onEnter(args) {
                const fd = args[0].toInt32();
                if (fd < 0) return;
                const peer = sockFds[fd];
                if (peer === undefined) return;                   // ordinary file I/O
                emit(fd, name, peer, this.threadId);
            }
        };
    }
    if (CLOSE_HOOKS.includes(name)) {
        return {
            onEnter(args) {
                const fd = args[0].toInt32();
                if (fd >= 0) delete sockFds[fd];
            }
        };
    }
    if (DUP_HOOKS.includes(name)) {
        return {
            onEnter(args) {
                this.dtOld = args[0].toInt32();
                const newFd = args[1].toInt32();
                if (newFd >= 0) delete sockFds[newFd];            // implicitly closed
            },
            onLeave(retval) {
                const result = retval.toInt32();
                if (result < 0 || this.dtOld === undefined) return;
                const peer = sockFds[this.dtOld];
                if (peer !== undefined) sockFds[result] = peer;
            }
        };
    }
    return null;
}

function installHooks() {
    const wanted = Object.keys(SOCKADDR_ON_ENTER)
        .concat(Object.keys(SOCKADDR_ON_LEAVE))
        .concat(MSGHDR_ON_ENTER, MSGHDR_ON_LEAVE, PEER_HOOKS, FD_HOOKS,
                CLOSE_HOOKS, DUP_HOOKS);

    const hooked = [];
    const failed = [];
    libc.enumerateExports().forEach(ex => {
        if (ex.type !== 'function' || !ex.name || !wanted.includes(ex.name)) return;
        const handler = handlerFor(ex.name);
        if (handler === null) return;
        try {
            Interceptor.attach(ex.address, handler);
            hooked.push(ex.name);
        } catch (e) {
            failed.push(ex.name);
        }
    });

    setTimeout(sendCounts, 500);
    setInterval(sendCounts, COUNTS_INTERVAL_MS);

    // A Java runtime with no working bridge is a broken run, not a quiet one.
    if (runtimePresent && !bridgeReady) {
        send({
            type: 'socket_trace_error', dump: 'socket_trace_meta.json', data_type: 'json',
            data: {
                error: 'java call-stack attribution unavailable: ' +
                       (bridgeError || 'bridge not initialised') +
                       ' — records will have no attribution',
                fatal_for_attribution: true
            }
        });
    }

    send({
        type: 'socket_trace_ready',
        dump: 'socket_trace_meta.json',
        data_type: 'json',
        data: {
            hooked,
            failed,
            missing: wanted.filter(n => !hooked.includes(n)),
            libc: libcName,
            platform: Process.platform,
            android_runtime: runtimePresent,
            java_bridge: bridgeReady,
            java_bridge_error: bridgeError,
            max_events: MAX_EVENTS,
            max_stacks_per_dest: MAX_STACKS_PER_DEST,
            max_walks_per_dest: MAX_WALKS_PER_DEST
        }
    });
}
