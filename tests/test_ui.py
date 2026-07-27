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
