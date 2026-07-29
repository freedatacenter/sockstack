"""A cleanup script is trusted with irreversible work, so its judgement about
what may be touched has to be tested harder than the touching itself.
"""
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                '..', 'scripts'))
import sweep  # noqa: E402


def make_run(root, name, files=('socket_trace.json',), age_days=0):
    path = os.path.join(root, name)
    os.makedirs(path, exist_ok=True)
    for filename in files:
        with open(os.path.join(path, filename), 'w') as out:
            out.write('x' * 100)
    stamp = time.time() - age_days * 86400
    os.utime(path, (stamp, stamp))
    return path


class WhatCountsAsARun(unittest.TestCase):
    def test_a_directory_with_a_trace_is_a_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(sweep.is_run(make_run(tmp, 'a')))

    def test_a_run_cut_short_still_counts(self):
        """No summary and no manifest — killed before it finished. That is the
        kind of leftover worth sweeping, not the kind to overlook."""
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(sweep.is_run(
                make_run(tmp, 'b', files=('sslkeylog.txt',))))

    def test_an_unrelated_directory_is_not_touched(self):
        with tempfile.TemporaryDirectory() as tmp:
            plain = os.path.join(tmp, 'notes')
            os.makedirs(plain)
            with open(os.path.join(plain, 'todo.md'), 'w') as out:
                out.write('hi')
            self.assertFalse(sweep.is_run(plain))
            self.assertEqual(sweep.find_runs([tmp]), [])

    def test_a_run_is_not_searched_for_runs_inside_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            outer = make_run(tmp, 'outer')
            make_run(outer, 'previous_run_20260101T000000Z')
            self.assertEqual(sweep.find_runs([tmp]), [outer])


class WhatGetsSpared(unittest.TestCase):
    def test_the_newest_runs_survive_however_old_they_are(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = [make_run(tmp, f'r{i}', age_days=100 + i) for i in range(5)]
            act, spare = sweep.plan(runs, older_than_days=7, keep=3)
            self.assertEqual(len(spare), 3)
            self.assertEqual(len(act), 2)

    def test_a_recent_run_is_spared_even_beyond_the_keep_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = [make_run(tmp, f'r{i}', age_days=0) for i in range(6)]
            act, _ = sweep.plan(runs, older_than_days=7, keep=3)
            self.assertEqual(act, [])

    def test_age_alone_does_not_take_the_last_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = [make_run(tmp, 'only', age_days=999)]
            act, spare = sweep.plan(runs, older_than_days=1, keep=1)
            self.assertEqual(act, [])
            self.assertEqual(spare, runs)


class WhatSlimmingRemoves(unittest.TestCase):
    """The findings stay; the capture, the session keys and the plaintext they
    opened do not. Getting this backwards would either destroy the evidence or
    keep the secrets."""

    def files(self):
        return ('socket_trace.json', 'run_manifest.json',
                'summary_20260101T000000Z.md', 'traffic.pcap',
                'decrypted.pcapng', 'sslkeylog.txt',
                'decrypted_bodies_20260101T000000Z.txt')

    def test_it_takes_the_capture_keys_and_bodies(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = make_run(tmp, 'a', files=self.files())
            names = {os.path.basename(f) for f in sweep.heavy_files(run)}
            self.assertEqual(names, {'traffic.pcap', 'decrypted.pcapng',
                                     'sslkeylog.txt',
                                     'decrypted_bodies_20260101T000000Z.txt'})

    def test_it_leaves_the_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = make_run(tmp, 'a', files=self.files())
            names = {os.path.basename(f) for f in sweep.heavy_files(run)}
            for kept in ('socket_trace.json', 'run_manifest.json',
                         'summary_20260101T000000Z.md'):
                self.assertNotIn(kept, names)

    def test_key_material_is_reported_where_it_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(sweep.holds_secrets(
                make_run(tmp, 'a', files=('sslkeylog.txt',))))
            self.assertFalse(sweep.holds_secrets(
                make_run(tmp, 'b', files=('socket_trace.json',))))


class NothingHappensWithoutSayingSo(unittest.TestCase):
    def test_a_dry_run_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = make_run(tmp, 'old', files=('socket_trace.json',
                                              'sslkeylog.txt'), age_days=99)
            sweep.main([tmp, '--older-than', '1', '--keep', '0'])
            self.assertTrue(os.path.exists(os.path.join(run, 'sslkeylog.txt')))

    def test_with_yes_the_keys_go_and_the_trace_stays(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = make_run(tmp, 'old', files=('socket_trace.json',
                                              'sslkeylog.txt'), age_days=99)
            sweep.main([tmp, '--older-than', '1', '--keep', '0', '--yes'])
            self.assertFalse(os.path.exists(os.path.join(run, 'sslkeylog.txt')))
            self.assertTrue(os.path.exists(os.path.join(run, 'socket_trace.json')))
            self.assertTrue(os.path.isdir(run))

    def test_remove_takes_the_directory_but_only_with_yes(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = make_run(tmp, 'old', age_days=99)
            sweep.main([tmp, '--older-than', '1', '--keep', '0', '--remove'])
            self.assertTrue(os.path.isdir(run))
            sweep.main([tmp, '--older-than', '1', '--keep', '0',
                        '--remove', '--yes'])
            self.assertFalse(os.path.exists(run))


if __name__ == '__main__':
    unittest.main()
