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


# Row 1 is verbatim from an Android 14 x86_64 emulator. Row 0 (a loopback
# listener) and row 2 (the same peer one address up, left in SYN_SENT) were
# added by hand to cover cases the captured sample did not contain.
PROC_NET_TCP = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:69A2 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 159278 1 0000000000000000 100 0 0 10 0
   1: 1002000A:EA5A 779AFB8E:01BB 01 00000000:00000000 00:00000000 00000000 10132        0 150158 1 0000000000000000 70 4 22 10 -1
   2: 1002000A:EA5B 779AFB8F:01BB 02 00000000:00000000 00:00000000 00000000 10132        0 150159 1 0000000000000000 70 4 22 10 -1
"""

# Verbatim rows from /proc/net/tcp6 on an Android 14 x86_64 emulator: an unbound
# listener, and an established connection whose address is IPv4-mapped.
PROC_NET_TCP6 = """\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:B281 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 167169 1 0000000000000000 100 0 0 10 0
   3: 0000000000000000FFFF00001002000A:CDC2 0000000000000000FFFF0000BC94FDAC:01BB 01 00000000:00000000 00:00000000 00000000 10131        0 132385 1 0000000000000000 95 4 31 10 -1
"""

PROC_NET_UDP = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  42: 1002000A:E5C1 0800000A:0035 07 00000000:00000000 00:00000000 00000000 10132        0 151002 2 0000000000000000 0
"""


def tables(**blocks):
    """The concatenation the device-side reader produces."""
    return ''.join(f'== {name}\n{body}' for name, body in blocks.items())


class ProcNetParsing(unittest.TestCase):
    """The kernel's socket table is the only view of the target's traffic that
    does not depend on the tracer having hooked the call. Misreading it would
    turn that safety net into a source of invented destinations."""

    def test_ipv4_address_is_little_endian_and_the_port_is_not(self):
        self.assertEqual(sockstack.decode_proc_addr('779AFB8E:01BB'),
                         ('142.251.154.119', 443))

    def test_ipv4_mapped_ipv6_is_reported_as_ipv4(self):
        # Both views must spell one address the same way, or the same host looks
        # like two and the cross-check reports a miss that never happened.
        self.assertEqual(
            sockstack.decode_proc_addr('0000000000000000FFFF0000BC94FDAC:01BB'),
            ('172.253.148.188', 443))

    def test_a_malformed_address_raises_rather_than_guesses(self):
        with self.assertRaises(ValueError):
            sockstack.decode_proc_addr('nonsense')

    def test_only_rows_owned_by_the_target_uid_are_kept(self):
        found = sockstack.parse_proc_net(tables(tcp=PROC_NET_TCP), 10132)
        self.assertEqual(set(found), {('142.251.154.119', 443, 'tcp'),
                                      ('143.251.154.119', 443, 'tcp')})
        self.assertEqual(sockstack.parse_proc_net(tables(tcp=PROC_NET_TCP), 10133), {})

    def test_a_connection_still_in_syn_sent_is_marked_unestablished(self):
        """A C2 that is down and being retried produces SYN_SENT rows. Reporting
        those as contacted destinations overstates what happened."""
        found = sockstack.parse_proc_net(tables(tcp=PROC_NET_TCP), 10132)
        self.assertTrue(found[('142.251.154.119', 443, 'tcp')])
        self.assertFalse(found[('143.251.154.119', 443, 'tcp')])

    def test_listening_sockets_are_not_destinations(self):
        self.assertEqual(sockstack.parse_proc_net(tables(tcp=PROC_NET_TCP), 0), {})

    def test_ipv6_table_is_parsed_with_the_same_uid_rule(self):
        found = sockstack.parse_proc_net(tables(tcp6=PROC_NET_TCP6), 10131)
        self.assertEqual(set(found), {('172.253.148.188', 443, 'tcp6')})

    def test_udp_is_read_too(self):
        """The tracer records UDP, so a cross-check that skipped it would be
        narrower than the thing it checks — and Go resolves DNS over a connected
        UDP socket, which is exactly the traffic this exists to catch."""
        found = sockstack.parse_proc_net(tables(udp=PROC_NET_UDP), 10132)
        self.assertEqual(set(found), {('10.0.0.8', 53, 'udp')})
        # UDP has no handshake; anything with a peer counts as used.
        self.assertTrue(found[('10.0.0.8', 53, 'udp')])

    def test_each_block_is_labelled_with_the_table_it_came_from(self):
        found = sockstack.parse_proc_net(
            tables(tcp=PROC_NET_TCP, udp=PROC_NET_UDP), 10132)
        self.assertEqual({proto for _, _, proto in found}, {'tcp', 'udp'})

    def test_a_truncated_row_is_skipped_not_fatal(self):
        self.assertEqual(sockstack.parse_proc_net('garbage\n1: 2: 3:\n', 10132), {})

    def test_no_input(self):
        self.assertEqual(sockstack.parse_proc_net('', 10132), {})


STAMP = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)


class KernelCrossCheck(unittest.TestCase):
    """A target whose networking bypasses libc leaves the tracer with nothing,
    and its traffic then looks like any other app's. The kernel's socket table
    tells the two apart — but only if the report distinguishes what it found
    from whether it was in a position to find anything."""

    def summarize(self, blob, tracer_ip='198.51.100.5', tracer_port=443):
        out = tempfile.mkdtemp()
        with open(os.path.join(out, 'socket_trace.json'), 'w') as fh:
            json.dump([{'peer_ip': tracer_ip, 'peer_port': tracer_port,
                        'socket_event_type': 'connect', 'stack_source': 'java',
                        'stack': [frame('com.example.A.go(A.java:1)')]}], fh)
        if blob is not None:
            with open(os.path.join(out, 'uid_sockets.json'), 'w') as fh:
                json.dump(blob, fh)
        sockstack.decrypt_and_summarize(out, 'com.example.app', stamp=STAMP)
        with open(os.path.join(out, 'summary_20260101T000000Z.md')) as fh:
            return fh.read()

    @staticmethod
    def blob(peers, status='ok', **extra):
        return {'uid': 10192, 'status': status, 'polls_succeeded': 3,
                'polls_failed': 0, 'shared_with': [],
                'peers': [{'ip': ip, 'port': port, 'proto': proto,
                           'established': established}
                          for ip, port, proto, established in peers], **extra}

    def test_a_destination_the_tracer_missed_is_reported_as_the_targets(self):
        report = self.summarize(self.blob([('203.0.113.9', 8443, 'tcp', True)]))
        self.assertIn('Traffic the tracer has no record of', report)
        self.assertIn('203.0.113.9:8443', report)
        self.assertIn('1 with no tracer record', report)

    def test_the_section_offers_reasons_rather_than_asserting_one(self):
        """Raw syscalls are one explanation among several — an idle socket held
        across an attach produces the same evidence — and naming only the
        exciting one would be the tool stating more than it knows."""
        report = self.summarize(self.blob([('203.0.113.9', 8443, 'tcp', True)]))
        self.assertIn('already open and idle when instrumentation attached', report)
        self.assertIn('raw syscalls', report)

    def test_an_unestablished_connection_is_not_called_a_contact(self):
        report = self.summarize(self.blob([('203.0.113.9', 8443, 'tcp', False)]))
        self.assertIn('attempted, never established', report)

    def test_a_second_port_on_a_known_address_is_still_a_miss(self):
        """Comparing addresses alone hides a second channel to a host the tracer
        already knows — a payload reusing the app's own CDN address on another
        port is precisely what wants flagging."""
        report = self.summarize(self.blob([('198.51.100.5', 9999, 'tcp', True)]))
        self.assertIn('198.51.100.5:9999', report)
        self.assertIn('1 with no tracer record', report)

    def test_agreement_produces_no_alarm(self):
        # A check that cried wolf on every well-behaved app would be ignored by
        # the time it mattered.
        report = self.summarize(self.blob([('198.51.100.5', 443, 'tcp', True)]))
        self.assertNotIn('Traffic the tracer has no record of', report)
        self.assertIn('0 with no tracer record', report)

    def test_an_unresolved_uid_is_reported_as_a_check_that_did_not_run(self):
        report = self.summarize(self.blob([], status='no-uid'))
        self.assertIn('Kernel cross-check did not run', report)
        self.assertNotIn('0 with no tracer record', report)

    def test_an_unreadable_proc_is_not_silence(self):
        """Empty because /proc was unreadable must not read like empty because
        there was nothing there."""
        report = self.summarize(self.blob([], status='unreadable', polls_failed=7))
        self.assertIn('Kernel cross-check failed', report)
        self.assertIn('7 attempt(s)', report)

    def test_a_shared_uid_is_declared_not_assumed_away(self):
        report = self.summarize(self.blob([('203.0.113.9', 8443, 'tcp', True)],
                                          shared_with=['com.other.app']))
        self.assertIn('is shared with com.other.app', report)

    def test_a_run_without_the_artifact_says_so_rather_than_staying_silent(self):
        """No line at all made four different situations look identical, one of
        which was 'the check agreed with the tracer'."""
        report = self.summarize(None)
        self.assertIn('no record for this run', report)


class UidResolution(unittest.TestCase):
    """`resolve_uid` decides whose sockets get relabelled as the target's. Both
    of its branches are string parsing over device output, and until this it was
    the only new function with no test at all."""

    LISTING = ('package:com.example.app uid:10192\n'
               'package:com.other.app uid:10193\n'
               'package:com.shared.a uid:10250\n'
               'package:com.shared.b uid:10250\n')

    def resolve(self, package, listing=None, stat_out=''):
        class Result:
            def __init__(self, stdout):
                self.stdout = stdout
                self.returncode = 0
        adb_original, priv_original = sockstack.adb, sockstack.priv
        sockstack.adb = lambda *a, **k: Result(self.LISTING if listing is None else listing)
        sockstack.priv = lambda *a, **k: Result(stat_out)
        try:
            return sockstack.resolve_uid('emulator-5554', package)
        finally:
            sockstack.adb, sockstack.priv = adb_original, priv_original

    def test_exact_package_match(self):
        self.assertEqual(self.resolve('com.example.app'), (10192, []))

    def test_a_shared_uid_names_the_other_packages(self):
        # Silently folding another package's sockets into the target's would be
        # the confident wrong answer this whole check exists to prevent.
        self.assertEqual(self.resolve('com.shared.a'), (10250, ['com.shared.b']))

    def test_a_frida_label_resolves_to_nothing_here(self):
        """Attaching names a process the way Frida does — `Chrome`, not
        `com.android.chrome` — which matches no package. The caller has to learn
        this rather than be handed a plausible wrong UID."""
        self.assertEqual(self.resolve('Chrome'), (None, []))

    def test_falls_back_to_the_data_directory_owner(self):
        self.assertEqual(self.resolve('com.example.app', listing='', stat_out='10199\n'),
                         (10199, []))

    def test_no_answer_anywhere(self):
        self.assertEqual(self.resolve('com.example.app', listing='', stat_out='?'),
                         (None, []))


class UidFromPid(unittest.TestCase):
    """The fallback that keeps the cross-check alive under --attach, which is
    the documented mode for samples with no launcher activity."""

    STATUS = 'Name:\tcom.example.app\nState:\tS (sleeping)\nUid:\t10192\t10192\t10192\t10192\n'

    def uid(self, status):
        class Result:
            stdout = status
            returncode = 0
        original = sockstack.priv
        sockstack.priv = lambda *a, **k: Result()
        try:
            return sockstack.uid_from_pid('emulator-5554', 4242)
        finally:
            sockstack.priv = original

    def test_reads_the_real_uid(self):
        self.assertEqual(self.uid(self.STATUS), 10192)

    def test_a_process_that_vanished_yields_nothing(self):
        self.assertIsNone(self.uid(''))


# --------------------------------------------------------------------------- ftrace source

# Shape of `trace_pipe` under sock:inet_sock_set_state. These are written to the
# format the kernel emits (comm-pid, cpu, flags, timestamp, event, k=v fields);
# no line here was captured from a device, so they test the parser's contract,
# not a particular kernel's spelling.
FTRACE_SYN = ('     curl-3421    [002] .... 12345.678901: inet_sock_set_state: '
              'family=AF_INET protocol=IPPROTO_TCP sport=45678 dport=443 '
              'saddr=10.0.2.15 daddr=142.250.185.78 saddrv6=::ffff:10.0.2.15 '
              'daddrv6=::ffff:142.250.185.78 oldstate=TCP_CLOSE newstate=TCP_SYN_SENT')
FTRACE_EST = FTRACE_SYN.replace('oldstate=TCP_CLOSE newstate=TCP_SYN_SENT',
                                'oldstate=TCP_SYN_SENT newstate=TCP_ESTABLISHED')
FTRACE_INBOUND = FTRACE_SYN.replace('oldstate=TCP_CLOSE newstate=TCP_SYN_SENT',
                                    'oldstate=TCP_SYN_RECV newstate=TCP_ESTABLISHED')


class FtraceEventParsing(unittest.TestCase):
    def test_a_connect_attempt_is_a_peer_that_is_not_established(self):
        event = sockstack.parse_ftrace_socket_event(FTRACE_SYN)
        self.assertEqual((event['ip'], event['port'], event['proto']),
                         ('142.250.185.78', 443, 'tcp'))
        self.assertFalse(event['established'])
        self.assertEqual((event['pid'], event['comm']), (3421, 'curl'))

    def test_the_far_end_answering_is_established(self):
        self.assertTrue(sockstack.parse_ftrace_socket_event(FTRACE_EST)['established'])

    def test_an_inbound_connection_is_not_somewhere_the_target_went(self):
        # LISTEN -> SYN_RECV -> ESTABLISHED. Its "peer" dialled in; counting it
        # would invent outbound traffic out of an open port.
        self.assertIsNone(sockstack.parse_ftrace_socket_event(FTRACE_INBOUND))

    def test_uninteresting_transitions_are_dropped(self):
        for states in ('oldstate=TCP_ESTABLISHED newstate=TCP_FIN_WAIT1',
                       'oldstate=TCP_CLOSE newstate=TCP_LISTEN',
                       'oldstate=TCP_FIN_WAIT2 newstate=TCP_CLOSE'):
            line = FTRACE_SYN.replace(
                'oldstate=TCP_CLOSE newstate=TCP_SYN_SENT', states)
            self.assertIsNone(sockstack.parse_ftrace_socket_event(line), states)

    def test_ipv6_is_read_from_the_v6_field(self):
        line = ('  Binder:1234_2-1567  [001] .... 99.9: inet_sock_set_state: '
                'family=AF_INET6 protocol=IPPROTO_TCP sport=39000 dport=8443 '
                'saddr=0.0.0.0 daddr=0.0.0.0 saddrv6=2a00:1450::1 '
                'daddrv6=2606:4700:4700::1111 '
                'oldstate=TCP_CLOSE newstate=TCP_SYN_SENT')
        event = sockstack.parse_ftrace_socket_event(line)
        self.assertEqual(event['ip'], '2606:4700:4700::1111')
        # comm containing dashes and digits must not eat the pid
        self.assertEqual((event['pid'], event['comm']), (1567, 'Binder:1234_2'))

    def test_a_mapped_v6_address_is_spelled_the_way_proc_net_spells_it(self):
        # Two spellings of one host would show up downstream as "the tracer
        # missed this", which is a finding invented by formatting.
        line = FTRACE_SYN.replace('family=AF_INET ', 'family=AF_INET6 ')
        self.assertEqual(sockstack.parse_ftrace_socket_event(line)['ip'],
                         '142.250.185.78')

    def test_a_tgid_column_does_not_shift_the_fields(self):
        line = ('     curl-3421  (  3400) [002] .... 12345.6: inet_sock_set_state: '
                'family=AF_INET protocol=IPPROTO_TCP sport=1 dport=443 '
                'saddr=10.0.2.15 daddr=1.2.3.4 '
                'oldstate=TCP_CLOSE newstate=TCP_SYN_SENT')
        event = sockstack.parse_ftrace_socket_event(line)
        self.assertEqual((event['pid'], event['ip'], event['port']),
                         (3421, '1.2.3.4', 443))

    def test_noise_and_truncation_are_not_crashes(self):
        for line in ('', '\n', 'CPU:0 [LOST 12 EVENTS]',
                     '# tracer: nop',
                     '     curl-3421    [002] .... 1.0: inet_sock_set_state:',
                     FTRACE_SYN.replace('dport=443', 'dport=notanumber'),
                     FTRACE_SYN[:60]):
            self.assertIsNone(sockstack.parse_ftrace_socket_event(line), repr(line))

    def test_an_unroutable_destination_is_not_a_peer(self):
        line = FTRACE_SYN.replace('daddr=142.250.185.78', 'daddr=0.0.0.0')
        self.assertIsNone(sockstack.parse_ftrace_socket_event(line))


class UidPidListing(unittest.TestCase):
    PS = ('  PID  UID\n'
          '  1234 10132\n'
          '  1300 10132\n'
          '  1400 1000\n'
          '  bad line\n')

    def test_only_the_targets_uid_is_kept(self):
        self.assertEqual(sockstack.parse_uid_pids(self.PS, 10132), [1234, 1300])

    def test_a_uid_with_nothing_running_is_empty_not_everything(self):
        self.assertEqual(sockstack.parse_uid_pids(self.PS, 10999), [])

    def test_junk_is_survivable(self):
        self.assertEqual(sockstack.parse_uid_pids('', 10132), [])
        self.assertEqual(sockstack.parse_uid_pids(None, 10132), [])


class MergeKernelSources(unittest.TestCase):
    POLLED = {'uid': 10132, 'status': 'ok', 'polls_succeeded': 5,
              'peers': [{'ip': '1.1.1.1', 'port': 443, 'proto': 'tcp',
                         'established': True},
                        {'ip': '8.8.8.8', 'port': 53, 'proto': 'udp',
                         'established': True}]}
    STREAMED = {'status': 'ok', 'event': 'sock/inet_sock_set_state',
                'events_parsed': 3, 'pids_filtered': [1234],
                'peers': [{'ip': '1.1.1.1', 'port': 443, 'proto': 'tcp',
                           'established': True},
                          {'ip': '5.6.7.8', 'port': 8080, 'proto': 'tcp',
                           'established': False}]}

    def test_both_sources_are_credited_for_an_address_both_saw(self):
        merged = sockstack.merge_kernel_sources(self.POLLED, self.STREAMED)
        entry = next(e for e in merged['peers'] if e['ip'] == '1.1.1.1')
        self.assertEqual(entry['sources'], ['proc-net', 'ftrace'])

    def test_what_polling_missed_is_named_as_such(self):
        merged = sockstack.merge_kernel_sources(self.POLLED, self.STREAMED)
        self.assertEqual([e['ip'] for e in merged['missed_by_polling']], ['5.6.7.8'])

    def test_udp_survives_the_merge_even_though_the_stream_cannot_see_it(self):
        merged = sockstack.merge_kernel_sources(self.POLLED, self.STREAMED)
        udp = next(e for e in merged['peers'] if e['proto'] == 'udp')
        self.assertEqual(udp['sources'], ['proc-net'])

    def test_an_established_sighting_wins_over_an_attempt(self):
        streamed = {'status': 'ok', 'peers': [
            {'ip': '9.9.9.9', 'port': 443, 'proto': 'tcp', 'established': True}]}
        polled = {'status': 'ok', 'peers': [
            {'ip': '9.9.9.9', 'port': 443, 'proto': 'tcp', 'established': False}]}
        merged = sockstack.merge_kernel_sources(polled, streamed)
        self.assertTrue(merged['peers'][0]['established'])

    def test_the_polled_artifact_is_unchanged_when_the_stream_never_ran(self):
        merged = sockstack.merge_kernel_sources(
            self.POLLED, {'status': 'no-tracefs', 'detail': 'x', 'peers': []})
        self.assertEqual([e['ip'] for e in merged['peers']], ['1.1.1.1', '8.8.8.8'])
        self.assertEqual(merged['missed_by_polling'], [])
        self.assertEqual(merged['ftrace']['status'], 'no-tracefs')

    def test_the_stream_alone_still_produces_an_artifact(self):
        merged = sockstack.merge_kernel_sources(
            {'uid': 10132, 'status': 'unreadable', 'peers': []}, self.STREAMED)
        self.assertEqual(len(merged['peers']), 2)
        self.assertEqual(len(merged['missed_by_polling']), 2)


# Verbatim `trace_pipe` output from a Linux 6.8 kernel: one curl to example.com,
# instance-local buffer, sock:inet_sock_set_state enabled. Kept exactly as the
# kernel wrote it, including `<...>` for a comm that was not in the cmdline map
# and `<idle>-0` for the transitions the kernel completes in softirq context.
FTRACE_REAL = """\
           <...>-2974095 [004] ..... 3794784.779392: inet_sock_set_state: family=AF_INET protocol=IPPROTO_TCP sport=0 dport=443 saddr=192.168.100.110 daddr=104.20.23.154 saddrv6=::ffff:192.168.100.110 daddrv6=::ffff:104.20.23.154 oldstate=TCP_CLOSE newstate=TCP_SYN_SENT
          <idle>-0       [003] ..s2. 3794784.785158: inet_sock_set_state: family=AF_INET protocol=IPPROTO_TCP sport=35032 dport=443 saddr=192.168.100.110 daddr=104.20.23.154 saddrv6=::ffff:192.168.100.110 daddrv6=::ffff:104.20.23.154 oldstate=TCP_SYN_SENT newstate=TCP_ESTABLISHED
            curl-2974095 [004] ..... 3794784.832531: inet_sock_set_state: family=AF_INET protocol=IPPROTO_TCP sport=35032 dport=443 saddr=192.168.100.110 daddr=104.20.23.154 saddrv6=::ffff:192.168.100.110 daddrv6=::ffff:104.20.23.154 oldstate=TCP_ESTABLISHED newstate=TCP_FIN_WAIT1
          <idle>-0       [003] ..s2. 3794784.837912: inet_sock_set_state: family=AF_INET protocol=IPPROTO_TCP sport=35032 dport=443 saddr=192.168.100.110 daddr=104.20.23.154 saddrv6=::ffff:192.168.100.110 daddrv6=::ffff:104.20.23.154 oldstate=TCP_FIN_WAIT1 newstate=TCP_CLOSING
          <idle>-0       [003] ..s2. 3794784.838126: inet_sock_set_state: family=AF_INET protocol=IPPROTO_TCP sport=35032 dport=443 saddr=192.168.100.110 daddr=104.20.23.154 saddrv6=::ffff:192.168.100.110 daddrv6=::ffff:104.20.23.154 oldstate=TCP_CLOSING newstate=TCP_CLOSE
"""


class FtraceAgainstRealKernelOutput(unittest.TestCase):
    """The fixtures above this were written from the documented format. These
    lines came off a running kernel, which is the only way to find out that the
    format was documented differently from how it is emitted."""

    def events(self):
        return [sockstack.parse_ftrace_socket_event(line)
                for line in FTRACE_REAL.splitlines()]

    def test_the_connect_and_the_handshake_are_the_only_two_kept(self):
        kept = [e for e in self.events() if e]
        self.assertEqual(len(kept), 2)
        self.assertEqual([e['established'] for e in kept], [False, True])

    def test_a_comm_the_kernel_could_not_name_still_yields_its_pid(self):
        self.assertEqual(self.events()[0]['pid'], 2974095)
        self.assertEqual(self.events()[0]['comm'], '<...>')

    def test_the_handshake_belongs_to_no_process(self):
        # The whole reason the pid filter has to include 0: this transition is
        # recorded in softirq context, not against the connecting task.
        self.assertEqual(self.events()[1]['pid'], 0)
        self.assertEqual(self.events()[1]['comm'], '<idle>')

    def test_the_connect_event_has_no_source_port_yet(self):
        # Which is why establishment cannot be correlated by source port.
        self.assertIn('sport=0', FTRACE_REAL.splitlines()[0])


class FtraceLedger(unittest.TestCase):
    def ledger(self):
        return sockstack.FtraceSocketEvents(serial=None)

    def test_a_real_session_ends_as_one_established_destination(self):
        led = self.ledger()
        for line in FTRACE_REAL.splitlines():
            led.note(sockstack.parse_ftrace_socket_event(line))
        artifact = led.artifact()
        self.assertEqual([(p['ip'], p['port'], p['established'])
                          for p in artifact['peers']],
                         [('104.20.23.154', 443, True)])
        self.assertEqual(artifact['established_from_softirq'], 1)

    def test_a_handshake_for_a_destination_we_never_dialled_is_ignored(self):
        # pid 0 carries the whole device's traffic. Accepting it wholesale would
        # hand the target every connection any app on the phone completed.
        led = self.ledger()
        stray = {'ip': '9.9.9.9', 'port': 443, 'proto': 'tcp',
                 'established': True, 'pid': 0, 'comm': '<idle>'}
        self.assertFalse(led.note(stray))
        self.assertEqual(led.artifact()['peers'], [])

    def test_an_attempt_that_is_never_completed_stays_an_attempt(self):
        led = self.ledger()
        led.note({'ip': '5.5.5.5', 'port': 8080, 'proto': 'tcp',
                  'established': False, 'pid': 1234, 'comm': 'app'})
        self.assertEqual(led.artifact()['peers'],
                         [{'ip': '5.5.5.5', 'port': 8080, 'proto': 'tcp',
                           'established': False}])

    def test_the_same_handshake_is_not_counted_twice(self):
        led = self.ledger()
        dial = {'ip': '1.2.3.4', 'port': 443, 'proto': 'tcp',
                'established': False, 'pid': 99, 'comm': 'app'}
        done = dict(dial, established=True, pid=0, comm='<idle>')
        led.note(dial)
        led.note(done)
        led.note(done)
        self.assertEqual(led.artifact()['established_from_softirq'], 1)

    def test_nothing_at_all_is_reported_as_such_not_as_success(self):
        artifact = self.ledger().artifact()
        self.assertEqual(artifact['status'], 'not-run')
        self.assertEqual(artifact['peers'], [])

    def test_a_running_source_that_saw_no_line_says_so(self):
        led = self.ledger()
        led.status = 'running'
        artifact = led.artifact()
        self.assertEqual(artifact['status'], 'no-events')
        self.assertIn('produced nothing', artifact['detail'])

    def test_the_artifact_states_what_the_source_cannot_see(self):
        self.assertEqual(self.ledger().artifact()['covers'], 'tcp')
