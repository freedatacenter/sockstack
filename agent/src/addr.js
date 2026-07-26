/*
 * Address parsing. Kept free of Frida globals so it can be unit-tested under
 * plain node — this is byte-level code and it is easy to get subtly wrong.
 */
'use strict';

const IS_DARWIN = typeof Process !== 'undefined' && Process.platform === 'darwin';

export function formatIPv6(groups) {
    // IPv4-mapped (::ffff:a.b.c.d) is far more readable in its dotted form.
    const mapped = groups[0] === 0 && groups[1] === 0 && groups[2] === 0 &&
                   groups[3] === 0 && groups[4] === 0 && groups[5] === 0xffff;
    if (mapped) {
        return `${(groups[6] >> 8) & 0xff}.${groups[6] & 0xff}.` +
               `${(groups[7] >> 8) & 0xff}.${groups[7] & 0xff}`;
    }
    // RFC 5952: compress the longest run of zero groups.
    let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
    for (let i = 0; i < 8; i++) {
        if (groups[i] === 0) {
            if (curStart < 0) { curStart = i; curLen = 0; }
            curLen++;
            if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
        } else {
            curStart = -1; curLen = 0;
        }
    }
    const parts = [];
    for (let k = 0; k < 8; k++) {
        if (bestLen > 1 && k === bestStart) { parts.push(''); k += bestLen - 1; continue; }
        parts.push(groups[k].toString(16));
    }
    let out = parts.join(':');
    if (bestLen > 1) {
        if (bestStart === 0) out = ':' + out;
        if (bestStart + bestLen === 8) out = out + ':';
    }
    return out;
}

export function parseSockaddr(addr, isDarwin = IS_DARWIN) {
    try {
        if (addr === null || addr === undefined || addr.isNull()) return null;
        // BSD/macOS sockaddr starts with uint8 sa_len, uint8 sa_family;
        // Linux starts with uint16 sa_family.
        const family = isDarwin ? addr.add(1).readU8() : addr.readU16();
        const port = (addr.add(2).readU8() << 8) | addr.add(3).readU8();
        if (family === 2) {                                    // AF_INET
            const o = addr.add(4);
            return {
                ip: [o.readU8(), o.add(1).readU8(), o.add(2).readU8(),
                     o.add(3).readU8()].join('.'),
                port
            };
        }
        // AF_INET6 is 10 on Linux, 30 on Darwin.
        if (family === (isDarwin ? 30 : 10)) {
            const groups = [];
            for (let i = 0; i < 8; i++) {
                groups.push((addr.add(8 + i * 2).readU8() << 8) | addr.add(9 + i * 2).readU8());
            }
            return { ip: formatIPv6(groups), port };
        }
    } catch (e) { /* not an address we can use */ }
    return null;
}

/* Frames that are identical for every caller and so cannot tell two call sites
 * apart. Kept deliberately in step with FRAMEWORK_PREFIXES in sockstack.py —
 * change one, change the other. Networking libraries (okhttp, Cronet…) are NOT
 * listed: their frames differ per call site, so they carry signal here even
 * though the report does not treat them as application code. */
const FRAMEWORK_PREFIXES = ['java.', 'javax.', 'android.', 'androidx.',
                            'libcore.', 'sun.', 'dalvik.', 'com.android.'];

/* The frames that identify *which* call site this is.
 *
 * Java stacks arrive innermost-first, so the top of a socket stack is always
 * the same libcore/java.net plumbing. Hashing a fixed window from the top gave
 * every caller reaching a host through java.net.Socket the same signature, and
 * the deduplicator then discarded every call site after the first — silently
 * deleting the one thing this tool exists to report. Drop the frames that
 * cannot discriminate, and keep the whole stack when nothing else remains. */
export function signatureFrames(frames) {
    const distinctive = frames.filter(
        s => !FRAMEWORK_PREFIXES.some(prefix => (s || '').startsWith(prefix)));
    return distinctive.length ? distinctive : frames;
}

export function hashFrames(frames) {
    const relevant = signatureFrames(frames);
    let h = 5381;
    for (let i = 0; i < relevant.length; i++) {
        const s = relevant[i] || '';
        for (let j = 0; j < s.length; j++) h = ((h * 33) ^ s.charCodeAt(j)) >>> 0;
    }
    return h.toString(16);
}
