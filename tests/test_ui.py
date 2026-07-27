"""
Unit tests for the web front-end's parsing — no device, no browser, no server.

The UI reads device output and turns it into things a person clicks. Misreading
any of it does not produce an error: it produces a page that confidently offers
the wrong device, the wrong package, or a tap in the wrong place.

    python3 -m unittest discover -s tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'ui'))
import server  # noqa: E402


# Verbatim `adb devices -l`, including a device that is present but unusable.
DEVICES = """List of devices attached
emulator-5554          device product:sdk_gphone64_x86_64 model:sdk_gphone64_x86_64 device:emu64xa
3A21FDH2001            unauthorized usb:1-1.2
R58N70ABCDE            device usb:1-3 product:a52qnaxx model:SM_A525F device:a52q
"""

PACKAGES = """package:org.fdroid.fdroid uid:10192
package:com.samplevpn.core uid:10193
package:com.k4m2p9.zx7qwd uid:10194
"""

DUMPS = """== org.fdroid.fdroid
firstInstallTime=2026-07-26 10:34:34
== com.samplevpn.core
firstInstallTime=2026-07-26 13:07:41
== com.k4m2p9.zx7qwd
firstInstallTime=2026-07-26 21:05:33
"""

# Shape taken from a real uiautomator dump of a dropper's fake Play Store page.
HIERARCHY = '''<?xml version='1.0' encoding='UTF-8'?>
<hierarchy rotation="0">
 <node index="0" text="" class="android.widget.FrameLayout" clickable="false" bounds="[0,0][1080,2400]">
  <node index="1" text="Update Available" resource-id="" class="android.widget.TextView"
        clickable="false" bounds="[42,300][900,380]" />
  <node index="2" text="MORE INFO" resource-id="com.k4m2p9.zx7qwd:id/moreInfoBtn"
        class="android.widget.Button" clickable="true" bounds="[42,1221][524,1347]" />
  <node index="3" text="UPDATE" resource-id="com.k4m2p9.zx7qwd:id/installUpdateBtn"
        class="android.widget.Button" clickable="true" bounds="[556,1221][1038,1347]" />
  <node index="4" text="" content-desc="Navigate up" resource-id=""
        class="android.widget.ImageButton" clickable="true" bounds="[0,0][0,0]" />
 </node>
</hierarchy>'''


class ParseDevices(unittest.TestCase):
    def test_reads_serial_state_and_model(self):
        found = server.parse_devices(DEVICES)
        self.assertEqual(found[0]['serial'], 'emulator-5554')
        self.assertEqual(found[0]['state'], 'device')
        self.assertEqual(found[2]['model'], 'SM A525F')

    def test_an_unusable_device_is_listed_not_hidden(self):
        """"No devices" while one is plugged in sends the reader after a cable
        problem; the real fix is accepting the prompt on the screen."""
        states = {d['serial']: d['state'] for d in server.parse_devices(DEVICES)}
        self.assertEqual(states['3A21FDH2001'], 'unauthorized')

    def test_the_header_line_is_not_a_device(self):
        self.assertEqual([d['serial'] for d in server.parse_devices(DEVICES)],
                         ['emulator-5554', '3A21FDH2001', 'R58N70ABCDE'])

    def test_no_devices(self):
        self.assertEqual(server.parse_devices('List of devices attached\n\n'), [])


class ParsePackages(unittest.TestCase):
    def test_newest_install_comes_first(self):
        # The package you want is nearly always the one you just installed, and
        # its name will not resemble the APK's filename.
        times = server.parse_install_times(DUMPS)
        names = [p['package'] for p in server.parse_packages(PACKAGES, times)]
        self.assertEqual(names[0], 'com.k4m2p9.zx7qwd')

    def test_uid_is_kept(self):
        found = server.parse_packages(PACKAGES, {})
        self.assertEqual({p['package']: p['uid'] for p in found}['org.fdroid.fdroid'],
                         10192)

    def test_without_install_times_the_list_is_still_ordered(self):
        names = [p['package'] for p in server.parse_packages(PACKAGES)]
        self.assertEqual(len(names), 3)

    def test_install_times_are_matched_to_their_package(self):
        self.assertEqual(server.parse_install_times(DUMPS)['com.samplevpn.core'],
                         '2026-07-26 13:07:41')


class ParseUiElements(unittest.TestCase):
    """A tap target read wrongly is a click that lands somewhere else — the
    exact failure this view exists to remove."""

    def test_only_clickable_nodes_become_targets(self):
        ids = {e['id'] for e in server.parse_ui_elements(HIERARCHY)}
        self.assertEqual(ids, {'moreInfoBtn', 'installUpdateBtn'})

    def test_centre_is_the_middle_of_the_bounds(self):
        found = {e['id']: e for e in server.parse_ui_elements(HIERARCHY)}
        self.assertEqual(found['installUpdateBtn']['center'], [797, 1284])

    def test_zero_sized_nodes_are_dropped(self):
        # A collapsed node reports clickable="true" with no area; offering it
        # would put a target at the corner of the screen.
        self.assertNotIn('', {e['id'] for e in server.parse_ui_elements(HIERARCHY)})

    def test_the_resource_id_is_shortened_to_its_name(self):
        found = {e['id']: e for e in server.parse_ui_elements(HIERARCHY)}
        self.assertIn('installUpdateBtn', found)
        self.assertEqual(found['installUpdateBtn']['text'], 'UPDATE')

    def test_content_description_survives_for_nodes_with_no_text(self):
        xml = ('<node content-desc="Search" class="android.widget.ImageButton" '
               'clickable="true" bounds="[10,10][60,60]" />')
        self.assertEqual(server.parse_ui_elements(xml)[0]['desc'], 'Search')

    def test_a_hierarchy_that_could_not_be_dumped(self):
        self.assertEqual(server.parse_ui_elements(''), [])


if __name__ == '__main__':
    unittest.main()


import json      # noqa: E402
import tempfile  # noqa: E402


def frame(text):
    return {'str': text, 'class': text.split('(')[0]}


class AttributionCards(unittest.TestCase):
    """The colour a peer gets is a claim. It says how well the tool knows who
    opened the socket — never how suspicious the address looks, which the tool
    has no way to judge and which an analyst must not be nudged towards."""

    def cards(self, records, uid=None):
        out = tempfile.mkdtemp()
        with open(os.path.join(out, 'socket_trace.json'), 'w') as fh:
            json.dump(records, fh)
        if uid is not None:
            with open(os.path.join(out, 'uid_sockets.json'), 'w') as fh:
                json.dump(uid, fh)
        return {c['peer']: c for c in server.attribution_cards(out)['cards']}

    @staticmethod
    def record(ip, port, source='java', stack=None):
        return {'peer_ip': ip, 'peer_port': port, 'socket_event_type': 'connect',
                'stack_source': source, 'stack': stack or []}

    def test_a_stack_naming_application_code_reads_as_known(self):
        found = self.cards([self.record('203.0.113.9', 443, stack=[
            frame('com.example.Beacon.ping(Beacon.java:8)')])])
        self.assertEqual(found['203.0.113.9:443']['kind'], 'app')
        self.assertEqual(found['203.0.113.9:443']['tone'], 'good')

    def test_a_library_only_stack_is_not_dressed_up_as_known(self):
        found = self.cards([self.record('203.0.113.9', 443, stack=[
            frame('okhttp3.internal.Http.send(Http.kt:1)')])])
        self.assertEqual(found['203.0.113.9:443']['tone'], 'partial')

    def test_an_unexamined_peer_is_flagged_louder_than_a_native_one(self):
        """"We did not look" must not look calmer than "we looked and it was
        native" — the report ranks them that way and so must the page."""
        found = self.cards([self.record('203.0.113.9', 443, source='not-walked'),
                            self.record('203.0.113.10', 443, source='native-thread')])
        self.assertEqual(found['203.0.113.9:443']['tone'], 'unknown')
        self.assertEqual(found['203.0.113.10:443']['tone'], 'partial')

    def test_a_broken_bridge_is_not_reported_as_native(self):
        found = self.cards([self.record('203.0.113.9', 443, source='no-bridge')])
        self.assertEqual(found['203.0.113.9:443']['kind'], 'attribution-unavailable')
        self.assertEqual(found['203.0.113.9:443']['tone'], 'unknown')

    def test_a_kernel_only_destination_appears_and_says_so(self):
        found = self.cards(
            [self.record('203.0.113.9', 443, stack=[frame('com.example.A.go(A.java:1)')])],
            uid={'uid': 10192, 'status': 'ok', 'peers': [
                {'ip': '203.0.113.50', 'port': 8443, 'proto': 'tcp', 'established': True}]})
        self.assertIn('203.0.113.50:8443', found)
        self.assertEqual(found['203.0.113.50:8443']['kind'], 'kernel-only')
        self.assertEqual(found['203.0.113.50:8443']['tone'], 'unknown')

    def test_no_kind_carries_a_verdict_about_the_address(self):
        """Nothing in the vocabulary should imply malice: the tool cannot tell a
        C2 from a CDN, and a red badge saying otherwise is a wrong answer stated
        confidently."""
        vocabulary = ' '.join(server.PEER_KINDS) + ' ' + \
                     ' '.join(label for label, _ in server.PEER_KINDS.values())
        for word in ('c2', 'malicious', 'suspicious', 'threat', 'clean', 'safe'):
            self.assertNotIn(word, vocabulary.lower())


# --------------------------------------------------------------------------- uploads

import re          # noqa: E402


class SafeUploadName(unittest.TestCase):
    """The filename comes from a browser, and the file it names is written to
    disk on the analysis host. Everything else here is about being right; this
    one is about not being climbed out of."""

    def test_an_ordinary_name_survives(self):
        self.assertEqual(server.safe_upload_name('target.apk'), 'target.apk')

    def test_a_path_is_reduced_to_its_basename(self):
        self.assertEqual(server.safe_upload_name('/etc/cron.d/target.apk'), 'target.apk')

    def test_a_windows_path_is_reduced_too(self):
        self.assertEqual(server.safe_upload_name(r'C:\Users\a\target.apk'), 'target.apk')

    def test_traversal_cannot_survive_in_any_form(self):
        for hostile in ('../../etc/passwd', '..', '....//evil.apk', '/../../x.apk'):
            self.assertNotIn('/', server.safe_upload_name(hostile))
            self.assertFalse(server.safe_upload_name(hostile).startswith('.'))

    def test_an_empty_name_still_produces_a_file(self):
        self.assertEqual(server.safe_upload_name(''), 'upload.apk')
        self.assertEqual(server.safe_upload_name(None), 'upload.apk')

    def test_a_long_name_is_bounded(self):
        self.assertLessEqual(len(server.safe_upload_name('a' * 400 + '.apk')), 120)

    def test_the_result_joins_to_a_path_inside_the_upload_directory(self):
        for hostile in ('../../etc/passwd', '/tmp/evil', 'ok.apk'):
            joined = os.path.join(server.UPLOAD_DIR, server.safe_upload_name(hostile))
            self.assertEqual(os.path.dirname(os.path.abspath(joined)),
                             os.path.abspath(server.UPLOAD_DIR))


# --------------------------------------------------------------------------- the page

INDEX = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'ui', 'index.html')


class Translations(unittest.TestCase):
    """Both languages come from one table in the page. A key present in one and
    missing from the other does not fail loudly — it renders the key itself, so
    the user reads `install.dropSub` where a sentence should be."""

    @classmethod
    def setUpClass(cls):
        with open(INDEX, encoding='utf-8') as fh:
            cls.page = fh.read()

    def table(self, lang):
        body = self.page.split(f'  {lang}: {{', 1)[1].split('\n  },', 1)[0]
        return set(re.findall(r"^\s*'([\w.]+)':", body, re.M))

    def test_both_languages_define_the_same_keys(self):
        self.assertEqual(self.table('en'), self.table('ru'))
        self.assertGreater(len(self.table('en')), 40)

    def test_every_key_the_markup_asks_for_exists(self):
        used = set(re.findall(r'data-i18n(?:-ph|-title)?="([\w.]+)"', self.page))
        self.assertTrue(used)
        self.assertEqual(used - self.table('en'), set())

    def test_every_key_the_script_asks_for_exists(self):
        used = set(re.findall(r"\bt\('([\w.]+)'", self.page))
        self.assertTrue(used)
        self.assertEqual(used - self.table('en'), set())

    def test_the_apk_can_be_chosen_from_both_screens(self):
        # The complaint that produced this: the install controls existed, but
        # only below a phone-sized frame on the second screen, where nobody
        # scrolled to find them.
        launch = self.page.split('id="launchView"', 1)[1].split('id="workView"', 1)[0]
        work = self.page.split('id="workView"', 1)[1]
        self.assertIn('id="apkDrop"', launch)
        self.assertIn('id="install"', launch)
        self.assertIn('id="install2"', work)
        # …and above the mirror, not under it.
        self.assertLess(work.index('id="install2"'), work.index('id="stage"'))


# --------------------------------------------------------------------------- connecting

class ConnectVerdict(unittest.TestCase):
    """`adb connect` exits 0 when it fails. Believing the exit status puts a
    device in the list that is not there, and the next thing the user does is
    start a run against nothing."""

    def test_a_connection_is_a_connection(self):
        self.assertTrue(server.connect_verdict(
            True, 'connected to 192.168.100.88:5555\n')['ok'])

    def test_already_connected_is_not_a_failure(self):
        self.assertTrue(server.connect_verdict(
            True, 'already connected to 192.168.100.88:5555\n')['ok'])

    def test_a_failure_that_exits_zero_is_still_a_failure(self):
        verdict = server.connect_verdict(
            True, 'failed to connect to 192.168.100.88:5555')
        self.assertFalse(verdict['ok'])
        self.assertIn('failed to connect', verdict['output'])

    def test_a_refused_connection_is_reported_in_adbs_own_words(self):
        verdict = server.connect_verdict(
            True, 'unable to connect to 10.0.0.5:5555: Connection refused')
        self.assertFalse(verdict['ok'])
        self.assertIn('Connection refused', verdict['output'])

    def test_a_missing_adb_is_a_failure_whatever_it_printed(self):
        self.assertFalse(server.connect_verdict(False, 'adb not found in PATH')['ok'])

    def test_silence_is_not_success(self):
        verdict = server.connect_verdict(True, '')
        self.assertFalse(verdict['ok'])
        self.assertTrue(verdict['output'])

    def test_pairing_is_judged_by_its_words_too(self):
        self.assertTrue(server.pair_verdict(
            True, 'Successfully paired to 192.168.100.88:37021 [guid=adb-x]')['ok'])
        self.assertFalse(server.pair_verdict(
            True, 'Failed: wrong pairing code')['ok'])


class NetworkDevice(unittest.TestCase):
    """Only a network device can be disconnected; offering it for a USB one is
    an offer to do nothing."""

    def test_host_and_port_is_a_network_device(self):
        self.assertTrue(server.is_network_device('192.168.100.88:5555'))
        self.assertTrue(server.is_network_device('emulator.stand.local:37021'))

    def test_a_usb_serial_is_not(self):
        self.assertFalse(server.is_network_device('39061FDJH00A3M'))
        self.assertFalse(server.is_network_device('emulator-5554'))

    def test_a_colon_alone_does_not_make_it_one(self):
        self.assertFalse(server.is_network_device('weird:serial'))
        self.assertFalse(server.is_network_device(':5555'))

    def test_the_device_list_carries_the_flag(self):
        listing = ('List of devices attached\n'
                   '192.168.100.88:5555   device product:x model:Stand device:y\n'
                   'emulator-5554         device product:z model:Emu device:w\n')
        got = {d['serial']: d['network'] for d in server.parse_devices(listing)}
        self.assertEqual(got, {'192.168.100.88:5555': True, 'emulator-5554': False})


class AdbServerLabel(unittest.TestCase):
    """Which adb server the page is talking to. The whole remote-stand recipe is
    pointing the client at a forwarded one, and nothing else on the page would
    show whether that took."""

    def setUp(self):
        self.saved = {k: os.environ.pop(k, None)
                      for k in ('ADB_SERVER_SOCKET', 'ANDROID_ADB_SERVER_PORT')}

    def tearDown(self):
        for key, value in self.saved.items():
            os.environ.pop(key, None)
            if value is not None:
                os.environ[key] = value

    def test_the_default_is_named_not_left_blank(self):
        self.assertEqual(server.adb_server_label(), 'tcp:127.0.0.1:5037')

    def test_a_forwarded_port_is_visible(self):
        os.environ['ANDROID_ADB_SERVER_PORT'] = '5038'
        self.assertEqual(server.adb_server_label(), 'tcp:127.0.0.1:5038')

    def test_an_explicit_socket_wins(self):
        os.environ['ANDROID_ADB_SERVER_PORT'] = '5038'
        os.environ['ADB_SERVER_SOCKET'] = 'tcp:10.0.0.9:5037'
        self.assertEqual(server.adb_server_label(), 'tcp:10.0.0.9:5037')


# --------------------------------------------------------------------------- traffic view

class PeerAddress(unittest.TestCase):
    def test_an_ordinary_peer(self):
        self.assertEqual(server.peer_address('1.2.3.4:443'), '1.2.3.4')

    def test_ipv6_keeps_its_colons(self):
        self.assertEqual(server.peer_address('[2606:4700::1111]:443'),
                         '2606:4700::1111')

    def test_an_address_with_no_port(self):
        self.assertEqual(server.peer_address('1.2.3.4'), '1.2.3.4')

    def test_nothing(self):
        self.assertEqual(server.peer_address(''), '')
        self.assertEqual(server.peer_address(None), '')


class StreamState(unittest.TestCase):
    """Read it, saw it and could not read it, never saw it. The middle one is
    the whole point: an app speaking its own protocol over a raw socket leaves
    TLS records nobody has keys for, and drawing that as an empty request list
    says "it sent nothing" — the opposite of what happened."""

    def setUp(self):
        self.calls = []
        self.saved = server.sockstack.tshark_fields

    def tearDown(self):
        server.sockstack.tshark_fields = self.saved

    def fake(self, rows, err=None):
        def fields(path, flt, *names):
            self.calls.append(flt)
            return rows, err
        server.sockstack.tshark_fields = fields

    def test_http_that_was_read_is_decrypted(self):
        self.fake([])
        self.assertEqual(server.stream_state('a.pcap', 'b.pcapng', '1.2.3.4', True),
                         'decrypted')
        self.assertEqual(self.calls, [])      # no need to ask

    def test_tls_with_no_readable_inside_is_not_silence(self):
        self.fake(['1', '2'])
        with tempfile.NamedTemporaryFile(suffix='.pcapng') as fh:
            self.assertEqual(server.stream_state('', fh.name, '1.2.3.4', False),
                             'encrypted')

    def test_a_peer_absent_from_the_capture_says_so(self):
        self.fake([])
        with tempfile.NamedTemporaryFile(suffix='.pcapng') as fh:
            self.assertEqual(server.stream_state('', fh.name, '1.2.3.4', False),
                             'absent')

    def test_a_broken_tshark_claims_nothing(self):
        # An error is not an answer; saying "absent" here would be a finding
        # invented out of a missing tool.
        self.fake([], 'tshark not installed')
        with tempfile.NamedTemporaryFile(suffix='.pcapng') as fh:
            self.assertEqual(server.stream_state('', fh.name, '1.2.3.4', False), '')

    def test_ipv6_uses_the_right_filter_field(self):
        self.fake([])
        with tempfile.NamedTemporaryFile(suffix='.pcapng') as fh:
            server.stream_state('', fh.name, '2606:4700::1111', False)
        self.assertTrue(self.calls[0].startswith('ipv6.addr'), self.calls)


class TrafficView(unittest.TestCase):
    def test_a_directory_with_no_capture_is_explained_not_blank(self):
        with tempfile.TemporaryDirectory() as tmp:
            got = server.traffic_view(tmp)
            self.assertFalse(got['ok'])
            self.assertIn('no capture', got['error'])

    def test_a_missing_directory_is_not_a_crash(self):
        self.assertFalse(server.traffic_view('/nonexistent/dir')['ok'])
        self.assertFalse(server.traffic_view('')['ok'])


class TrafficIsWhereTheCallSiteIs(unittest.TestCase):
    """It was first built as a tab in the strip at the foot of the page, which
    meant clicking in one place and reading the answer in another — and nothing
    said the frames were clickable at all."""

    @classmethod
    def setUpClass(cls):
        with open(INDEX, encoding='utf-8') as fh:
            cls.page = fh.read()

    def test_the_drawer_is_rendered_inside_the_peer_card(self):
        card = self.page.split('class="peer ${card.tone}"', 1)[1].split('`;', 1)[0]
        self.assertIn('class="drawer', card)
        self.assertIn('class="reveal"', card)

    def test_the_bottom_strip_holds_the_log_and_nothing_else(self):
        strip = self.page.split('class="logstrip"', 1)[1].split('</div>\n</div>', 1)[0]
        self.assertIn('id="log"', strip)
        self.assertNotIn('id="traffic"', strip)
        self.assertNotIn('tabTraffic', self.page)

    def test_the_control_says_what_it_does(self):
        # A clickable region with no label is not a control, it is a rumour.
        self.assertIn("t('traffic.open')", self.page)


class RenderBody(unittest.TestCase):
    """A decrypted body is as likely to be protobuf as JSON. Rendered as UTF-8,
    the useful parts — versions, package names, identifiers — drown in
    replacement characters."""

    def test_text_stays_text(self):
        body = server.render_body(b'{"user":"anna","ok":true}')
        self.assertFalse(body['binary'])
        self.assertEqual(body['text'], '{"user":"anna","ok":true}')
        self.assertEqual(body['hex'], '')

    def test_protobuf_is_offered_as_its_printable_runs(self):
        raw = (b'\xca\x02\x05\x10\xa5\x07\x08\x03\n\x054.0.0\x12\x14'
               b'\x18\xd2\x02!\n\x0726.22.1\x12\x0cru.oneme.app\x00\xff\xfe')
        body = server.render_body(raw)
        self.assertTrue(body['binary'])
        self.assertIn('4.0.0', body['text'])
        self.assertIn('ru.oneme.app', body['text'])
        # and the bytes remain reachable rather than being summarised away
        self.assertIn('00000000', body['hex'])

    def test_short_runs_are_noise_and_are_left_out(self):
        body = server.render_body(b'\x00\x01ab\x02\x03cd\x04' * 8)
        self.assertTrue(body['binary'])
        self.assertEqual(body['text'], '')

    def test_the_hexdump_carries_an_ascii_gutter(self):
        body = server.render_body(b'\x00' * 4 + b'HTTP' + b'\xff' * 8)
        first = body['hex'].splitlines()[0]
        self.assertTrue(first.startswith('00000000  '))
        self.assertTrue(first.endswith('....HTTP........'))

    def test_a_huge_body_is_bounded_and_says_it_was_cut(self):
        body = server.render_body(b'A' * (server.BODY_CHARS + 500))
        self.assertTrue(body['clipped'])
        self.assertEqual(len(body['text']), server.BODY_CHARS)

    def test_an_empty_body_is_not_called_binary(self):
        self.assertFalse(server.render_body(b'')['binary'])
