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
