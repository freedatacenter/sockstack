"""
Unit tests for sockstack's pure logic — no device, no Frida, no friTap.

    python3 -m unittest discover -s tests -v
"""
import datetime
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import sockstack  # noqa: E402


def frame(text):
    return {'str': text, 'class': text.split('(')[0]}


class ClassifyStack(unittest.TestCase):
    def test_application_frame_is_kept(self):
        app, net = sockstack.classify_stack([frame('com.example.Sync.upload(Sync.java:42)')])
        self.assertEqual(app, ['com.example.Sync.upload(Sync.java:42)'])
        self.assertEqual(net, [])

    def test_framework_frames_are_dropped(self):
        app, net = sockstack.classify_stack([
            frame('java.net.Socket.connect(Socket.java:1)'),
            frame('android.os.Handler.run(Handler.java:2)'),
            frame('libcore.io.IoBridge.read(IoBridge.java:3)'),
        ])
        self.assertEqual(app, [])
        self.assertEqual(net, [])

    def test_network_library_is_separated_from_application_code(self):
        # The whole point of the split: okhttp is nearest, but it is not the answer.
        app, net = sockstack.classify_stack([
            frame('okhttp3.internal.connection.RealConnection.connect(RealConnection.kt:9)'),
            frame('java.lang.Thread.run(Thread.java:1)'),
            frame('com.example.api.Client.post(Client.java:7)'),
        ])
        self.assertEqual(app, ['com.example.api.Client.post(Client.java:7)'])
        self.assertEqual(net, ['okhttp3.internal.connection.RealConnection.connect(RealConnection.kt:9)'])

    def test_handles_missing_and_malformed_frames(self):
        app, net = sockstack.classify_stack([None, {}, {'str': ''},
                                              frame('com.example.A.b(A.java:1)')])
        self.assertEqual(app, ['com.example.A.b(A.java:1)'])
        self.assertEqual(net, [])

    def test_none_stack(self):
        self.assertEqual(sockstack.classify_stack(None), ([], []))


class AggregateCounts(unittest.TestCase):
    def test_sums_per_peer_and_operation(self):
        totals = sockstack.aggregate_counts({
            'connect|1.2.3.4|443': 2,
            'send|1.2.3.4|443': 5,
        })
        self.assertEqual(totals['1.2.3.4:443 connect'], 2)
        self.assertEqual(totals['1.2.3.4:443 send'], 5)

    def test_ipv6_keys_survive_the_split_and_are_bracketed(self):
        # The key separator is '|', so colons inside an IPv6 literal are safe;
        # the rendered peer must bracket the literal to stay unambiguous.
        totals = sockstack.aggregate_counts({'connect|2a02:ec80:300::1|443': 3})
        self.assertEqual(totals['[2a02:ec80:300::1]:443 connect'], 3)

    def test_ignores_malformed_keys(self):
        self.assertEqual(dict(sockstack.aggregate_counts({'nonsense': 1})), {})

    def test_empty(self):
        self.assertEqual(dict(sockstack.aggregate_counts(None)), {})


class FormatPeer(unittest.TestCase):
    def test_ipv4_is_plain(self):
        self.assertEqual(sockstack.format_peer('1.2.3.4', 443), '1.2.3.4:443')

    def test_ipv6_is_bracketed(self):
        self.assertEqual(sockstack.format_peer('2a02:ec80::1', 443), '[2a02:ec80::1]:443')


class SummarizeTrace(unittest.TestCase):
    def test_counts_take_precedence_over_record_tallies(self):
        records = [{'peer_ip': '1.2.3.4', 'peer_port': 443, 'socket_event_type': 'recv'}]
        peers, _, _, _ = sockstack.summarize_trace(records, {'recv|1.2.3.4|443': 53})
        # 53 operations were collapsed into one stored record; the total must
        # reflect the traffic, not the number of records kept.
        self.assertEqual(peers['1.2.3.4:443 recv'], 53)

    def test_falls_back_to_record_tallies_without_counts(self):
        records = [{'peer_ip': '1.2.3.4', 'peer_port': 443, 'socket_event_type': 'recv'}]
        peers, _, _, _ = sockstack.summarize_trace(records, None)
        self.assertEqual(peers['1.2.3.4:443 recv'], 1)

    def test_attribution_reports_application_frame_and_library(self):
        records = [{
            'peer_ip': '1.2.3.4', 'peer_port': 443, 'socket_event_type': 'connect',
            'stack': [frame('okhttp3.internal.Http.send(Http.kt:1)'),
                      frame('com.example.Beacon.ping(Beacon.java:8)')],
        }]
        _, attribution, unattributed, _ = sockstack.summarize_trace(records)
        self.assertEqual(len(attribution), 1)
        self.assertEqual(attribution[0]['peer'], '1.2.3.4:443')
        self.assertEqual(attribution[0]['app_frames'], ['com.example.Beacon.ping(Beacon.java:8)'])
        self.assertEqual(attribution[0]['via'], 'okhttp3.internal.Http.send(Http.kt:1)')
        self.assertEqual(unattributed, {})

    def test_distinct_call_sites_to_one_peer_are_both_reported(self):
        records = [
            {'peer_ip': '1.2.3.4', 'peer_port': 443, 'socket_event_type': 'connect',
             'stack': [frame('com.example.A.go(A.java:1)')]},
            {'peer_ip': '1.2.3.4', 'peer_port': 443, 'socket_event_type': 'connect',
             'stack': [frame('com.example.B.go(B.java:1)')]},
        ]
        _, attribution, _, _ = sockstack.summarize_trace(records)
        self.assertEqual(len(attribution), 2)

    def test_identical_call_sites_are_deduplicated(self):
        rec = {'peer_ip': '1.2.3.4', 'peer_port': 443, 'socket_event_type': 'connect',
               'stack': [frame('com.example.A.go(A.java:1)')]}
        _, attribution, _, _ = sockstack.summarize_trace([dict(rec), dict(rec)])
        self.assertEqual(len(attribution), 1)

    def test_call_sites_differing_only_deep_in_a_library_are_both_kept(self):
        """The bug this guards: the runner rebuilt its own dedup key from the
        application frames plus only the FIRST library frame, while the agent's
        signature covers every non-framework frame. Two call sites that share
        their application frames and diverge deeper inside okhttp were two
        records to the agent and one line in the report — an undercount of the
        one number this tool exists to produce.

        The previous test in this class uses stacks with *different* application
        frames, so it passes either way and cannot catch this.
        """
        def rec(signature, second_lib):
            return {'peer_ip': '1.2.3.4', 'peer_port': 443,
                    'socket_event_type': 'write', 'stack_source': 'java',
                    'stack_signature': signature,
                    'stack': [frame('okhttp3.internal.Http.send(Http.kt:1)'),
                              frame(second_lib),
                              frame('com.example.A.go(A.java:1)')]}
        records = [rec('sig-a', 'okio.Sink.write(JvmOkio.kt:56)'),
                   rec('sig-b', 'okio.Source.read(JvmOkio.kt:93)')]
        _, attribution, _, _ = sockstack.summarize_trace(records)
        self.assertEqual(len(attribution), 2)
        # And they must not print identically, or the reader discards one.
        self.assertNotEqual(attribution[0]['via'], attribution[1]['via'])

    def test_call_sites_differing_below_the_displayed_frames_are_distinguished(self):
        """Real case from a malware run: two paths share their three nearest
        application frames and diverge on the fourth. Deduplication keeps both,
        but printed with only three frames they are the same line twice — and a
        reader discards one as a glitch. The display has to reach deeper."""
        def rec(signature, fourth):
            return {'peer_ip': '1.2.3.4', 'peer_port': 9999,
                    'socket_event_type': 'sendto', 'stack_source': 'java',
                    'stack_signature': signature,
                    'stack': [frame('com.obf.ca0.j(Unknown Source:96)'),
                              frame('com.obf.ca0.e(Unknown Source:12)'),
                              frame('com.obf.wf1.H(Unknown Source:7)'),
                              frame(fourth)]}
        records = [rec('sig-a', 'com.obf.ka0.e(Unknown Source:12)'),
                   rec('sig-b', 'com.obf.mc.l(Unknown Source:7)')]
        _, attribution, _, _ = sockstack.summarize_trace(records)
        self.assertEqual(len(attribution), 2)
        self.assertNotEqual(attribution[0]['app_frames'], attribution[1]['app_frames'])

    def test_a_group_that_splits_unevenly_is_disambiguated_to_the_end(self):
        """Three call sites entering the library at the same frame. The first
        depth at which they differ separates one of them and leaves the other
        two identical to each other — those diverge two frames deeper. A single
        extension pass treats the group as handled and prints two of the three
        lines the same way.

        Real case, F-Droid over okhttp: `readConnectionPreface` and the frame
        reading loop both sit under `RealBufferedSource.request`, while a third
        read enters through `RealBufferedSource.read` and splits off early. The
        earlier fix covered groups of two, where one pass is enough.
        """
        def rec(signature, tail):
            return {'peer_ip': '1.2.3.4', 'peer_port': 443,
                    'socket_event_type': 'read', 'stack_source': 'java',
                    'stack_signature': signature,
                    'stack': [frame('okio.InputStreamSource.read(JvmOkio.kt:93)'),
                              frame('okio.AsyncTimeout$source$1.read(AsyncTimeout.kt:153)')]
                             + [frame(text) for text in tail]}
        shared = ['okio.RealBufferedSource.request(RealBufferedSource.kt:63)',
                  'okhttp3.internal.http2.Http2Reader.nextFrame(Http2Reader.kt:89)']
        records = [
            rec('sig-a', shared + ['okhttp3.internal.http2.Http2Reader'
                                   '.readConnectionPreface(Http2Reader.kt:73)']),
            rec('sig-b', shared + ['okhttp3.internal.http2.Http2Connection$ReaderRunnable'
                                   '.invoke(Http2Connection.kt:618)']),
            rec('sig-c', ['okio.RealBufferedSource.read(RealBufferedSource.kt:42)']),
        ]
        _, attribution, _, _ = sockstack.summarize_trace(records)
        self.assertEqual(len(attribution), 3)
        rendered = {(item['peer'], tuple(item['app_frames']), item['via'])
                    for item in attribution}
        self.assertEqual(len(rendered), 3, 'two entries render identically')

    def test_disambiguation_terminates_on_stacks_it_cannot_separate(self):
        """Two records the agent called distinct, whose visible frames are the
        same to the last one. Nothing can tell them apart in the display, and
        the loop must stop rather than spin looking for a frame that is not
        there."""
        def rec(signature):
            return {'peer_ip': '1.2.3.4', 'peer_port': 443,
                    'socket_event_type': 'read', 'stack_source': 'java',
                    'stack_signature': signature,
                    'stack': [frame('okio.Source.read(JvmOkio.kt:93)')]}
        _, attribution, _, _ = sockstack.summarize_trace([rec('sig-a'), rec('sig-b')])
        self.assertEqual(len(attribution), 2)

    def test_identical_signatures_still_collapse(self):
        rec = {'peer_ip': '1.2.3.4', 'peer_port': 443, 'socket_event_type': 'write',
               'stack_source': 'java', 'stack_signature': 'sig-a',
               'stack': [frame('com.example.A.go(A.java:1)')]}
        _, attribution, _, _ = sockstack.summarize_trace([dict(rec), dict(rec)])
        self.assertEqual(len(attribution), 1)

    def test_older_artifacts_without_a_signature_use_the_full_library_chain(self):
        """Records captured before the agent emitted a signature must still be
        deduplicated on every library frame, not just the first."""
        def rec(second_lib):
            return {'peer_ip': '1.2.3.4', 'peer_port': 443,
                    'socket_event_type': 'write', 'stack_source': 'java',
                    'stack': [frame('okhttp3.internal.Http.send(Http.kt:1)'),
                              frame(second_lib),
                              frame('com.example.A.go(A.java:1)')]}
        records = [rec('okio.Sink.write(JvmOkio.kt:56)'),
                   rec('okio.Source.read(JvmOkio.kt:93)')]
        _, attribution, _, _ = sockstack.summarize_trace(records)
        self.assertEqual(len(attribution), 2)

    def test_records_without_a_peer_are_skipped(self):
        peers, attribution, unattributed, partial = \
            sockstack.summarize_trace([{'peer_ip': ''}])
        self.assertEqual(dict(peers), {})
        self.assertEqual(attribution, [])
        self.assertEqual(unattributed, {})
        self.assertEqual(partial, [])


def stackless(ip, source, port=443, op='sendto'):
    return {'peer_ip': ip, 'peer_port': port, 'socket_event_type': op,
            'stack': None, 'stack_source': source}


class UnattributedReasons(unittest.TestCase):
    """The report must never present ignorance as knowledge.

    Only `native-thread` means "this call site is native". Every other reason
    for a missing stack means the tool did not, or could not, look — and saying
    "native code" about those is a confident wrong answer.
    """

    def bucket(self, records):
        _, _, unattributed, _ = sockstack.summarize_trace(records)
        return unattributed

    def test_each_source_maps_to_its_own_reason(self):
        cases = {
            'native-thread': 'native-thread',
            'not-walked': 'not-examined',
            'no-bridge': 'attribution-unavailable',
            'stack-error': 'attribution-unavailable',
            'no-runtime': 'no-runtime',
            None: 'unknown',
            'something-new': 'unknown',
        }
        for source, reason in cases.items():
            with self.subTest(source=source):
                self.assertEqual(
                    self.bucket([stackless('1.2.3.4', source)]),
                    {reason: ['1.2.3.4:443']})

    def test_every_tracer_source_is_covered(self):
        """A new stack_source in the agent must not fall silently into a bucket
        that claims more than we know. `unknown` is the safe landing place, and
        it is ranked above `native-thread` so it can never be read as native."""
        self.assertLess(sockstack._REASON_ORDER['unknown'],
                        sockstack._REASON_ORDER['native-thread'])

    def test_unwalked_peer_is_never_called_native(self):
        reasons = self.bucket([stackless('192.0.2.10', 'not-walked', 9999)])
        self.assertEqual(reasons, {'not-examined': ['192.0.2.10:9999']})
        self.assertNotIn('native-thread', reasons)

    def test_mixed_reasons_report_the_most_conceding_one(self):
        records = [stackless('1.2.3.4', 'native-thread'),
                   stackless('1.2.3.4', 'not-walked')]
        self.assertEqual(self.bucket(records), {'not-examined': ['1.2.3.4:443']})

    def test_java_stack_without_application_frames_is_not_native(self):
        rec = {'peer_ip': '1.2.3.4', 'peer_port': 443, 'socket_event_type': 'connect',
               'stack_source': 'java',
               'stack': [frame('java.net.Socket.connect(Socket.java:646)'),
                         frame('libcore.io.IoBridge.connect(IoBridge.java:179)')]}
        self.assertEqual(self.bucket([rec]), {'framework-only': ['1.2.3.4:443']})

    def test_attributed_peer_never_appears_as_unattributed(self):
        """Reproduces the shape of a real malware run, with the live C2 replaced
        by a TEST-NET address.

        The bug this guards: a peer with both an attributed record and an
        unwalked one was listed under call-stack attribution AND under "native
        code — Cronet, JNI, or a non-JVM runtime", in the same report, for the
        same C2 address.
        """
        records = [
            {'peer_ip': '192.0.2.10', 'peer_port': 9999,
             'socket_event_type': 'connect', 'stack_source': 'java',
             'stack': [frame('com.example.obf.la0.c(Unknown Source:68)')]},
            stackless('192.0.2.10', 'not-walked', 9999),
        ]
        _, attribution, unattributed, partial = sockstack.summarize_trace(records)
        self.assertEqual(len(attribution), 1)
        self.assertEqual(unattributed, {})
        self.assertEqual(partial, ['192.0.2.10:9999'])


class UnknownTsharkField(unittest.TestCase):
    """An older tshark not knowing a field is a capability gap, not a fault in
    the capture, and must not be reported to the analyst as an analysis problem."""

    def test_recognises_the_wordings_tshark_uses(self):
        for message in [
            '"http2.body.reassembled.data" is neither a field nor a protocol name.',
            'tshark: Some fields aren\'t valid: http2.body.reassembled.data',
            'Unknown display filter: foo.bar',
        ]:
            with self.subTest(message=message):
                self.assertTrue(sockstack.UNKNOWN_FIELD_RE.search(message))

    def test_does_not_swallow_a_real_failure(self):
        for message in ['The file "x.pcap" appears to be damaged',
                        'Permission denied']:
            with self.subTest(message=message):
                self.assertFalse(sockstack.UNKNOWN_FIELD_RE.search(message))


class DevicePresent(unittest.TestCase):
    LISTING = ('List of devices attached\n'
               'emulator-5554\tdevice\n'
               'emulator-55540\toffline\n')

    def test_exact_match_not_substring(self):
        # A substring test would have matched emulator-55540 here.
        self.assertEqual(sockstack.device_present('emulator-5554', self.LISTING), 'device')
        self.assertEqual(sockstack.device_present('emulator-55540', self.LISTING), 'offline')

    def test_absent_device(self):
        self.assertIsNone(sockstack.device_present('emulator-1', self.LISTING))

    def test_empty_listing(self):
        self.assertIsNone(sockstack.device_present('emulator-5554', ''))


class LoadRecords(unittest.TestCase):
    def test_prefers_the_finalized_array(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, 'socket_trace.json'), 'w') as fh:
                json.dump([{'peer_ip': '1.1.1.1'}], fh)
            with open(os.path.join(d, 'socket_trace.jsonl'), 'w') as fh:
                fh.write('{"peer_ip": "2.2.2.2"}\n')
            self.assertEqual(sockstack._load_records(d), [{'peer_ip': '1.1.1.1'}])

    def test_falls_back_to_the_incremental_log(self):
        # This is the path that matters after a run was cut short.
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, 'socket_trace.jsonl'), 'w') as fh:
                fh.write('{"peer_ip": "2.2.2.2"}\n{"peer_ip": "3.3.3.3"}\n')
            self.assertEqual(sockstack._load_records(d),
                             [{'peer_ip': '2.2.2.2'}, {'peer_ip': '3.3.3.3'}])

    def test_tolerates_a_truncated_final_line(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, 'socket_trace.jsonl'), 'w') as fh:
                fh.write('{"peer_ip": "2.2.2.2"}\n{"peer_ip": "3.3.')
            self.assertEqual(sockstack._load_records(d), [{'peer_ip': '2.2.2.2'}])

    def test_no_artifacts(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(sockstack._load_records(d), [])


class PrepareOutput(unittest.TestCase):
    def test_moves_stale_artifacts_aside_and_restricts_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, 'run')
            os.makedirs(out)
            stale = os.path.join(out, 'traffic.pcap')
            open(stale, 'w').close()
            old_report = os.path.join(out, 'summary_20260101T000000Z.md')
            open(old_report, 'w').close()
            keep = os.path.join(out, 'notes.txt')
            open(keep, 'w').close()
            archive = sockstack.prepare_output(out)
            # A stale capture must never be summarized as if it belonged to this run.
            self.assertFalse(os.path.exists(stale))
            # Timestamped reports are matched by pattern, not by exact name.
            self.assertFalse(os.path.exists(old_report))
            self.assertTrue(os.path.exists(keep))
            self.assertEqual(os.stat(out).st_mode & 0o777, 0o700)
            # Evidence is preserved, not destroyed: a rerun into the same
            # directory must not be the way a capture is lost for good.
            self.assertTrue(os.path.exists(os.path.join(archive, 'traffic.pcap')))
            self.assertTrue(os.path.exists(
                os.path.join(archive, 'summary_20260101T000000Z.md')))

    def test_returns_none_when_there_is_nothing_to_archive(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, 'run')
            self.assertIsNone(sockstack.prepare_output(out))
            self.assertEqual(os.listdir(out), [])


class Bodies(unittest.TestCase):
    def test_identical_bodies_are_collapsed(self):
        hexed = b'{"a":1}'.hex()
        self.assertEqual(sockstack.extract_bodies([hexed, hexed]), ['{"a":1}'])

    def test_api_payloads_sort_before_markup(self):
        html = b'<!DOCTYPE html><html><body>x</body></html>'.hex()
        js = b'{"token":"secret"}'.hex()
        bodies = sockstack.extract_bodies([html, js])
        self.assertTrue(bodies[0].startswith('{'), bodies[0][:40])

    def test_invalid_hex_is_skipped(self):
        self.assertEqual(sockstack.extract_bodies(['zzzz', b'ok'.hex()]), ['ok'])

    def test_ranking(self):
        self.assertLess(sockstack.body_rank('{"a":1}'),
                        sockstack.body_rank('<!DOCTYPE html><html>'))


class TracerIps(unittest.TestCase):
    def test_collects_from_records_and_counts(self):
        ips = sockstack.tracer_ips([{'peer_ip': '1.2.3.4'}],
                                    {'connect|5.6.7.8|443': 1})
        self.assertEqual(ips, {'1.2.3.4', '5.6.7.8'})

    def test_ipv6_key_is_recovered_whole(self):
        ips = sockstack.tracer_ips([], {'connect|2a02:ec80::1|443': 1})
        self.assertEqual(ips, {'2a02:ec80::1'})

    def test_empty(self):
        self.assertEqual(sockstack.tracer_ips(None, None), set())


class SplitRow(unittest.TestCase):
    def test_pads_missing_trailing_columns(self):
        # tshark omits trailing empty fields entirely.
        self.assertEqual(sockstack.split_row('a\tb', 4), ['a', 'b', '', ''])

    def test_first_addr_prefers_the_populated_family(self):
        self.assertEqual(sockstack.first_addr('', '2a02::1'), '2a02::1')
        self.assertEqual(sockstack.first_addr('1.2.3.4,5.6.7.8', ''), '1.2.3.4')


if __name__ == '__main__':
    unittest.main(verbosity=2)


class DeviceArch(unittest.TestCase):
    """Frida's releases are named by architecture, not by Android ABI. A hint
    that echoes the ABI back — `frida-server-…-android-arm64-v8a` — points at a
    file that has never existed, and the reader who follows it concludes the
    download is broken rather than their guess."""

    def arch_for(self, abi):
        class Result:
            stdout = abi + '\n'
        original = sockstack.adb
        sockstack.adb = lambda *args, **kwargs: Result()
        try:
            return sockstack.device_arch('emulator-5554')
        finally:
            sockstack.adb = original

    def test_arm64_abi_maps_to_the_frida_release_name(self):
        self.assertEqual(self.arch_for('arm64-v8a'), ('arm64-v8a', 'arm64'))

    def test_arm32_abi_maps_to_the_frida_release_name(self):
        self.assertEqual(self.arch_for('armeabi-v7a'), ('armeabi-v7a', 'arm'))

    def test_x86_64_is_named_the_same_by_both(self):
        self.assertEqual(self.arch_for('x86_64'), ('x86_64', 'x86_64'))

    def test_an_unrecognised_abi_does_not_invent_a_filename(self):
        self.assertEqual(self.arch_for('riscv64'), ('riscv64', '<arch>'))

    def test_a_silent_device_is_reported_as_unknown(self):
        self.assertEqual(self.arch_for(''), ('unknown', '<arch>'))


PROC_NET_TCP = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:69A2 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 159278 1 0000000000000000 100 0 0 10 0
   1: 1002000A:EA5A 779AFB8E:01BB 08 00000000:00000000 00:00000000 00000000 10132        0 150158 1 0000000000000000 70 4 22 10 -1
"""

# Real rows from /proc/net/tcp6 on an Android 14 emulator: an unbound listener,
# and a connection whose address is IPv4-mapped.
PROC_NET_TCP6 = """\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:B281 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 167169 1 0000000000000000 100 0 0 10 0
   1: 0000000000000000FFFF00001002000A:A97C 0000000000000000FFFF0000BC944BAD:01BB 01 00000000:00000000 00:00000000 00000000 10131        0 122249 1 0000000000000000 100 0 0 10 0
"""


class ProcNetParsing(unittest.TestCase):
    """The kernel's socket table is the only view of the target's traffic that
    does not depend on the tracer having hooked the call. Misreading it would
    turn that safety net into a source of invented destinations."""

    def test_ipv4_address_is_little_endian_and_the_port_is_not(self):
        self.assertEqual(sockstack.decode_proc_addr('779AFB8E:01BB'),
                         ('142.251.154.119', 443))

    def test_ipv4_mapped_ipv6_is_reported_as_ipv4(self):
        # Both tables must spell one address the same way, or the same host
        # looks like two and the cross-check reports a phantom miss.
        self.assertEqual(
            sockstack.decode_proc_addr('0000000000000000FFFF0000BC944BAD:01BB'),
            ('173.75.148.188', 443))

    def test_a_malformed_address_raises_rather_than_guesses(self):
        with self.assertRaises(ValueError):
            sockstack.decode_proc_addr('nonsense')

    def test_only_rows_owned_by_the_target_uid_are_kept(self):
        self.assertEqual(sockstack.parse_proc_net(PROC_NET_TCP, 10132),
                         {('142.251.154.119', 443)})
        self.assertEqual(sockstack.parse_proc_net(PROC_NET_TCP, 10133), set())

    def test_listening_sockets_are_not_destinations(self):
        # Row 0 is owned by uid 0 with remote port 0; a listener is not somewhere
        # the target went.
        self.assertEqual(sockstack.parse_proc_net(PROC_NET_TCP, 0), set())

    def test_ipv6_table_is_parsed_with_the_same_uid_rule(self):
        self.assertEqual(sockstack.parse_proc_net(PROC_NET_TCP6, 10131),
                         {('173.75.148.188', 443)})

    def test_a_truncated_row_is_skipped_not_fatal(self):
        self.assertEqual(sockstack.parse_proc_net('garbage\n1: 2: 3:\n', 10132), set())

    def test_no_input(self):
        self.assertEqual(sockstack.parse_proc_net('', 10132), set())


STAMP = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)


class KernelCrossCheck(unittest.TestCase):
    """A target whose networking bypasses libc leaves the tracer with nothing,
    and its traffic then looks exactly like another app's. The kernel's socket
    table is what tells the two apart — and saying so is the whole point, so the
    summary has to surface it rather than quietly widen the target set."""

    def summarize(self, uid_peers, tracer_ip='198.51.100.5'):
        out = tempfile.mkdtemp()
        with open(os.path.join(out, 'socket_trace.json'), 'w') as fh:
            json.dump([{'peer_ip': tracer_ip, 'peer_port': 443,
                        'socket_event_type': 'connect', 'stack_source': 'java',
                        'stack': [frame('com.example.A.go(A.java:1)')]}], fh)
        with open(os.path.join(out, 'uid_sockets.json'), 'w') as fh:
            json.dump({'uid': 10192,
                       'peers': [{'ip': ip, 'port': port} for ip, port in uid_peers]}, fh)
        sockstack.decrypt_and_summarize(out, 'com.example.app', stamp=STAMP)
        with open(os.path.join(out, 'summary_20260101T000000Z.md')) as fh:
            return fh.read()

    def test_a_destination_the_tracer_missed_is_reported_as_the_targets(self):
        report = self.summarize([('203.0.113.9', 8443)])
        self.assertIn('Traffic the tracer never saw', report)
        self.assertIn('203.0.113.9:8443', report)
        self.assertIn('1 unseen by the tracer', report)

    def test_agreement_produces_no_alarm(self):
        # The tracer already saw this one: a cross-check that cries wolf on every
        # well-behaved app would be ignored by the time it mattered.
        report = self.summarize([('198.51.100.5', 443)])
        self.assertNotIn('Traffic the tracer never saw', report)
        self.assertIn('0 unseen by the tracer', report)

    def test_without_the_cross_check_the_line_is_absent_entirely(self):
        out = tempfile.mkdtemp()
        with open(os.path.join(out, 'socket_trace.json'), 'w') as fh:
            json.dump([], fh)
        sockstack.decrypt_and_summarize(out, 'com.example.app', stamp=STAMP)
        with open(os.path.join(out, 'summary_20260101T000000Z.md')) as fh:
            report = fh.read()
        self.assertNotIn('Kernel cross-check', report)
