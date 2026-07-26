/*
 * Unit tests for the agent's address parsing (agent/src/addr.js).
 *
 * No Frida and no device: a Buffer-backed fake pointer exercises the real
 * byte-level code.
 *
 *     node tests/test_agent_addr.mjs
 */
import assert from 'assert';
import { formatIPv6, parseSockaddr, hashFrames, signatureFrames } from '../agent/src/addr.js';

function ptr(buffer, offset = 0) {
    return {
        isNull: () => buffer === null,
        add: n => ptr(buffer, offset + n),
        readU8: () => buffer.readUInt8(offset),
        readU16: () => buffer.readUInt16LE(offset),
        readU32: () => buffer.readUInt32LE(offset)
    };
}

function sockaddrIn(ip, port) {
    const b = Buffer.alloc(16);
    b.writeUInt16LE(2, 0);                                  // AF_INET
    b.writeUInt16BE(port, 2);                               // network byte order
    ip.split('.').forEach((o, i) => b.writeUInt8(parseInt(o, 10), 4 + i));
    return ptr(b);
}

function sockaddrIn6(groups, port) {
    const b = Buffer.alloc(28);
    b.writeUInt16LE(10, 0);                                 // AF_INET6
    b.writeUInt16BE(port, 2);
    for (let i = 0; i < 8; i++) b.writeUInt16BE(groups[i], 8 + i * 2);  // past flowinfo
    return ptr(b);
}

function sockaddrDarwin(ip, port) {
    const b = Buffer.alloc(16);
    b.writeUInt8(16, 0);                                    // sa_len
    b.writeUInt8(2, 1);                                     // sa_family
    b.writeUInt16BE(port, 2);
    ip.split('.').forEach((o, i) => b.writeUInt8(parseInt(o, 10), 4 + i));
    return ptr(b);
}

let failures = 0;
function check(name, fn) {
    try { fn(); console.log('  ok   ' + name); }
    catch (e) { failures++; console.log('  FAIL ' + name + '\n       ' + e.message); }
}

console.log('formatIPv6');
check('compresses the longest zero run', () =>
    assert.strictEqual(formatIPv6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]), '2001:db8::1'));
check('compresses a middle zero run only', () =>
    assert.strictEqual(formatIPv6([0x2606, 0x4700, 0x10, 0, 0, 0, 0x6814, 0x179a]),
        '2606:4700:10::6814:179a'));
check('renders the loopback', () =>
    assert.strictEqual(formatIPv6([0, 0, 0, 0, 0, 0, 0, 1]), '::1'));
check('renders the unspecified address', () =>
    assert.strictEqual(formatIPv6([0, 0, 0, 0, 0, 0, 0, 0]), '::'));
check('leaves a single zero group uncompressed', () =>
    assert.strictEqual(formatIPv6([1, 0, 2, 3, 4, 5, 6, 7]), '1:0:2:3:4:5:6:7'));
check('renders IPv4-mapped in dotted form', () =>
    assert.strictEqual(formatIPv6([0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304]), '1.2.3.4'));
check('does not invent a compression when there are no zeros', () =>
    assert.strictEqual(formatIPv6([0x2a02, 0xec80, 0x300, 0xed1a, 1, 2, 3, 4]),
        '2a02:ec80:300:ed1a:1:2:3:4'));

console.log('parseSockaddr');
check('parses AF_INET with a big-endian port', () =>
    assert.deepStrictEqual(parseSockaddr(sockaddrIn('203.0.113.10', 443), false),
        { ip: '203.0.113.10', port: 443 }));
check('parses a high port correctly', () =>
    assert.deepStrictEqual(parseSockaddr(sockaddrIn('10.0.0.1', 65535), false),
        { ip: '10.0.0.1', port: 65535 }));
check('parses AF_INET6 past the flowinfo field', () =>
    assert.deepStrictEqual(
        parseSockaddr(sockaddrIn6([0x2a02, 0xec80, 0x300, 0xed1a, 0, 0, 0, 1], 443), false),
        { ip: '2a02:ec80:300:ed1a::1', port: 443 }));
check('reads the family past sa_len on darwin', () =>
    assert.deepStrictEqual(parseSockaddr(sockaddrDarwin('1.2.3.4', 80), true),
        { ip: '1.2.3.4', port: 80 }));
check('returns null for an unsupported family (AF_UNIX)', () => {
    const b = Buffer.alloc(16);
    b.writeUInt16LE(1, 0);
    assert.strictEqual(parseSockaddr(ptr(b), false), null);
});
check('returns null for a null pointer', () =>
    assert.strictEqual(parseSockaddr(ptr(null), false), null));

console.log('hashFrames');
check('is stable for identical stacks', () =>
    assert.strictEqual(hashFrames(['a.B.c(A.java:1)']), hashFrames(['a.B.c(A.java:1)'])));
check('differs for different call sites', () =>
    assert.notStrictEqual(hashFrames(['a.B.c(A.java:1)']), hashFrames(['a.B.d(A.java:2)'])));

/* A real Android socket stack is innermost-first, so its first frames are always
 * the same libcore/java.net plumbing no matter who called. Hashing a fixed window
 * from the top gave every caller the same signature and the deduplicator then
 * dropped every call site after the first — deleting the one thing this tool
 * reports. These two stacks differ only at depth 12. */
const PLUMBING = [
    'libcore.io.Linux.connect(Native Method)',
    'libcore.io.ForwardingOs.connect(ForwardingOs.java:201)',
    'libcore.io.BlockGuardOs.connect(BlockGuardOs.java:158)',
    'libcore.io.ForwardingOs.connect(ForwardingOs.java:201)',
    'libcore.io.IoBridge.connectErrno(IoBridge.java:218)',
    'libcore.io.IoBridge.connect(IoBridge.java:179)',
    'java.net.PlainSocketImpl.socketConnect(PlainSocketImpl.java:142)',
    'java.net.AbstractPlainSocketImpl.doConnect(AbstractPlainSocketImpl.java:390)',
    'java.net.AbstractPlainSocketImpl.connectToAddress(AbstractPlainSocketImpl.java:230)',
    'java.net.AbstractPlainSocketImpl.connect(AbstractPlainSocketImpl.java:212)',
    'java.net.SocksSocketImpl.connect(SocksSocketImpl.java:436)',
    'java.net.Socket.connect(Socket.java:646)'
];
check('distinguishes call sites that differ only below the plumbing', () =>
    assert.notStrictEqual(
        hashFrames(PLUMBING.concat(['k7v2p9x4m1qz.la0.c(Unknown Source:68)'])),
        hashFrames(PLUMBING.concat(['k7v2p9x4m1qz.ca0.j(Unknown Source:96)']))));
check('ignores plumbing depth when the caller is the same', () =>
    assert.strictEqual(
        hashFrames(PLUMBING.concat(['k7v2p9x4m1qz.la0.c(Unknown Source:68)'])),
        hashFrames(PLUMBING.slice(0, 4).concat(['k7v2p9x4m1qz.la0.c(Unknown Source:68)']))));
check('keeps networking-library frames, which do discriminate', () =>
    assert.notStrictEqual(
        hashFrames(['okhttp3.internal.Http.send(Http.kt:1)', 'com.example.A.go(A.java:1)']),
        hashFrames(['okhttp3.internal.Http.send(Http.kt:9)', 'com.example.A.go(A.java:1)'])));

console.log('signatureFrames');
check('drops framework frames', () =>
    assert.deepStrictEqual(signatureFrames(PLUMBING.concat(['com.example.A.go(A.java:1)'])),
        ['com.example.A.go(A.java:1)']));
check('falls back to the whole stack when everything is framework', () =>
    assert.deepStrictEqual(signatureFrames(PLUMBING), PLUMBING));

console.log(failures ? `\n${failures} test(s) failed` : '\nall tests passed');
process.exit(failures ? 1 : 0);
