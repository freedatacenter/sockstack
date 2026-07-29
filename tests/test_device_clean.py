"""Uninstalling is irreversible and it happens on someone else's device, so the
decision about what to remove is tested far harder than the removal itself.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                '..', 'scripts'))
import device_clean  # noqa: E402

LISTING = (
    'package:org.fdroid.fdroid  installer=null uid:10192\r\n'
    'package:ru.example.target  installer=com.android.vending uid:10195\r\n'
    'package:com.example.sample  installer=null uid:10197\r\n'
)


class ReadingTheListing(unittest.TestCase):
    def test_names_installers_and_uids_come_through(self):
        got = device_clean.parse_listing(LISTING)
        self.assertEqual([p['name'] for p in got],
                         ['com.example.sample', 'org.fdroid.fdroid',
                          'ru.example.target'])
        by_name = {p['name']: p for p in got}
        self.assertEqual(by_name['ru.example.target']['installer'],
                         'com.android.vending')
        self.assertEqual(by_name['com.example.sample']['uid'], '10197')

    def test_a_null_installer_is_reported_as_no_installer(self):
        """`installer=null` is a sideload — on an analysis device, a sample or a
        tool. Carrying the literal string 'null' into the output would make it
        look like a package installed by something called null."""
        got = {p['name']: p for p in device_clean.parse_listing(LISTING)}
        self.assertEqual(got['org.fdroid.fdroid']['installer'], '')

    def test_noise_around_the_listing_is_ignored(self):
        got = device_clean.parse_listing('List of packages\n\n' + LISTING)
        self.assertEqual(len(got), 3)

    def test_an_empty_listing_is_not_a_crash(self):
        self.assertEqual(device_clean.parse_listing(''), [])
        self.assertEqual(device_clean.parse_listing(None), [])


class DecidingWhatGoes(unittest.TestCase):
    def setUp(self):
        self.packages = device_clean.parse_listing(LISTING)

    def test_nothing_is_selected_by_default(self):
        wanted, _, _ = device_clean.choose(self.packages, [], [], False)
        self.assertEqual(wanted, [])

    def test_named_packages_are_selected(self):
        wanted, _, _ = device_clean.choose(
            self.packages, ['com.example.sample'], [], False)
        self.assertEqual(wanted, ['com.example.sample'])

    def test_keep_beats_an_explicit_remove(self):
        """If naming a package for removal could override the protection you set
        on it, the protection is decoration."""
        wanted, spared, _ = device_clean.choose(
            self.packages, ['ru.example.target'], ['ru.example.target'], False)
        self.assertEqual(wanted, [])
        self.assertEqual(spared, ['ru.example.target'])

    def test_keep_beats_remove_all(self):
        wanted, spared, _ = device_clean.choose(
            self.packages, [], ['ru.example.target'], True)
        self.assertNotIn('ru.example.target', wanted)
        self.assertEqual(len(wanted), 2)
        self.assertEqual(spared, ['ru.example.target'])

    def test_a_package_that_is_not_there_is_reported_not_silently_dropped(self):
        wanted, _, missing = device_clean.choose(
            self.packages, ['com.example.sample', 'com.example.ghost'], [], False)
        self.assertEqual(wanted, ['com.example.sample'])
        self.assertEqual(missing, ['com.example.ghost'])

    def test_remove_all_never_reaches_beyond_the_listing(self):
        """Only what `pm list packages -3` returned. System packages are not
        this script's business, and a device that will not boot is a worse
        outcome than a cluttered one."""
        wanted, _, _ = device_clean.choose(self.packages, [], [], True)
        self.assertEqual(set(wanted), {p['name'] for p in self.packages})


class ReportingTheResult(unittest.TestCase):
    def test_only_success_counts_as_removed(self):
        real = device_clean.adb
        try:
            device_clean.adb = lambda *a, **k: type(
                'R', (), {'stdout': 'Success\n', 'stderr': '', 'returncode': 0})()
            self.assertTrue(device_clean.uninstall('x', 'com.example.sample')[0])

            device_clean.adb = lambda *a, **k: type(
                'R', (), {'stdout': 'Failure [DELETE_FAILED_INTERNAL_ERROR]',
                          'stderr': '', 'returncode': 0})()
            ok, detail = device_clean.uninstall('x', 'com.example.sample')
            self.assertFalse(ok)
            self.assertIn('DELETE_FAILED', detail)
        finally:
            device_clean.adb = real

    def test_silence_from_adb_is_not_read_as_success(self):
        real = device_clean.adb
        try:
            device_clean.adb = lambda *a, **k: type(
                'R', (), {'stdout': '', 'stderr': '', 'returncode': 0})()
            ok, detail = device_clean.uninstall('x', 'com.example.sample')
            self.assertFalse(ok)
            self.assertIn('nothing', detail)
        finally:
            device_clean.adb = real


if __name__ == '__main__':
    unittest.main()
