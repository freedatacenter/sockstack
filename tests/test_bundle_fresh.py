"""The shipped agent bundle must match the sources it was built from.

`scripts/frida/socket_trace.bundle.js` is a build artifact that ships in the
tree, so nothing stops someone editing `agent/src/` and forgetting to rebuild.
The tracer would then keep running the previous behaviour while the sources
claim the new one — and every finding would be attributed to code that never
executed.

The build is byte-for-byte reproducible, so the check is a rebuild and a
compare. It skips when the toolchain is not installed, because the rest of the
suite is deliberately runnable with no npm and no device.
"""
import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENT = os.path.join(ROOT, 'agent')
BUNDLE = os.path.join(ROOT, 'scripts', 'frida', 'socket_trace.bundle.js')
COMPILER = os.path.join(AGENT, 'node_modules', '.bin', 'frida-compile')


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


class BundleFresh(unittest.TestCase):
    def test_bundle_matches_agent_sources(self):
        if not os.path.exists(BUNDLE):
            self.fail(f'{BUNDLE} is missing — run `cd agent && npm ci && npm run build`')
        if not shutil.which('node') or not os.path.exists(COMPILER):
            self.skipTest('agent toolchain not installed (cd agent && npm ci)')

        with tempfile.TemporaryDirectory() as tmp:
            rebuilt = os.path.join(tmp, 'socket_trace.bundle.js')
            result = subprocess.run(
                [COMPILER, 'src/index.js', '-o', rebuilt],
                cwd=AGENT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0,
                             f'frida-compile failed:\n{result.stderr}')
            self.assertEqual(
                sha256(rebuilt), sha256(BUNDLE),
                'the shipped bundle is stale — agent/src has changed since it '
                'was built. Run `cd agent && npm run build`.')


if __name__ == '__main__':
    unittest.main()
