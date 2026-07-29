#!/usr/bin/env python3
"""sweep.py — retire old runs without throwing away what they proved.

A run directory holds two very different things. The findings — the trace, the
summary, the manifest — are small, and they are the reason the run happened. The
capture is most of the bytes, and alongside it sit the TLS session keys and the
decrypted bodies they unlocked. Keeping the first forever is archiving; keeping
the second forever is hoarding somebody's session keys on a lab machine because
nobody got round to it.

So the default is not deletion, it is **slimming**: drop the capture, the keylog
and the decrypted bodies; keep the summary and the trace. The run stays readable
as a record and stops being a place where secrets accumulate. `--remove` is
available when the whole thing is scratch.

Nothing is deleted without `--yes`. A directory is only ever touched when it
looks like a run — a stray path that merely sits under the same parent is not
one, and this script will not be the reason someone loses a folder.

    ./scripts/sweep.py ~                       # show what would happen
    ./scripts/sweep.py ~ --older-than 3
    ./scripts/sweep.py ~ --yes                 # slim them
    ./scripts/sweep.py ~ --remove --yes        # delete them outright
"""
import argparse
import os
import shutil
import sys
import time

# What makes a directory a run. Any one of these is enough — a run cut short
# before the summary was written is still a run, and is exactly the kind of
# leftover worth sweeping.
RUN_MARKERS = ('socket_trace.json', 'socket_trace.jsonl', 'run_manifest.json',
               'sslkeylog.txt', 'traffic.pcap')

# Bytes that are either large, secret, or both. Removing these is the whole
# point: `sslkeylog.txt` is the session keys, `decrypted.pcapng` and the bodies
# are what those keys opened.
HEAVY = ('traffic.pcap', 'decrypted.pcapng', 'sslkeylog.txt')
HEAVY_PREFIXES = ('decrypted_bodies_',)

# Kept by slimming, because they are the findings rather than the material.
SECRET_FILES = ('sslkeylog.txt', 'decrypted.pcapng')


def is_run(path):
    return os.path.isdir(path) and any(
        os.path.exists(os.path.join(path, name)) for name in RUN_MARKERS)


def heavy_files(path):
    """The removable files in a run: large, secret, or regenerable."""
    out = []
    for name in sorted(os.listdir(path)):
        full = os.path.join(path, name)
        if not os.path.isfile(full):
            continue
        if name in HEAVY or name.startswith(HEAVY_PREFIXES):
            out.append(full)
    return out


def holds_secrets(path):
    """Session keys or the plaintext they produced, still on disk."""
    names = set(os.listdir(path)) if os.path.isdir(path) else set()
    return bool([n for n in names
                 if n in SECRET_FILES or n.startswith('decrypted_bodies_')])


def dir_size(path):
    total = 0
    for root, _, files in os.walk(path):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                pass
    return total


def find_runs(roots, depth=2):
    """Run directories under `roots`, without descending into a run itself."""
    found = []
    for root in roots:
        root = os.path.abspath(os.path.expanduser(root))
        if not os.path.isdir(root):
            continue
        if is_run(root):
            found.append(root)
            continue
        for current, dirs, _ in os.walk(root):
            if current.count(os.sep) - root.count(os.sep) >= depth:
                dirs[:] = []
                continue
            for name in list(dirs):
                full = os.path.join(current, name)
                if is_run(full):
                    found.append(full)
                    dirs.remove(name)        # a run has no runs inside it
    return sorted(set(found))


def plan(runs, older_than_days, keep, now=None):
    """(to_act, to_spare) — newest first, age and count both respected.

    `keep` wins over age on purpose. "Older than a week" is a guess about what
    matters; "the last three runs" is the thing an operator actually reaches for
    when something breaks, and a sweep that takes those away teaches people to
    stop running the sweep.
    """
    now = time.time() if now is None else now
    dated = sorted(((os.path.getmtime(p), p) for p in runs), reverse=True)
    spare = [p for _, p in dated[:keep]]
    cutoff = now - older_than_days * 86400
    act = [p for stamp, p in dated[keep:] if stamp < cutoff]
    spare += [p for stamp, p in dated[keep:] if stamp >= cutoff]
    return act, spare


def human(size):
    for unit in ('B', 'K', 'M', 'G'):
        if size < 1024 or unit == 'G':
            return f'{size:.0f}{unit}' if unit == 'B' else f'{size:.1f}{unit}'
        size /= 1024
    return f'{size:.1f}G'


def main(argv=None):
    ap = argparse.ArgumentParser(
        description='Retire old sockstack runs; slim by default, never silently.')
    ap.add_argument('roots', nargs='*', default=[os.getcwd()],
                    help='where to look (default: the current directory)')
    ap.add_argument('--older-than', type=int, default=7, metavar='DAYS',
                    help='only touch runs older than this (default: 7)')
    ap.add_argument('--keep', type=int, default=3, metavar='N',
                    help='always spare the N newest runs (default: 3)')
    ap.add_argument('--remove', action='store_true',
                    help='delete the whole run instead of slimming it')
    ap.add_argument('--yes', action='store_true',
                    help='actually do it; without this nothing is written')
    args = ap.parse_args(argv)

    runs = find_runs(args.roots)
    if not runs:
        print('no run directories found under: ' + ', '.join(args.roots))
        return 0

    act, spare = plan(runs, args.older_than, args.keep)
    verb = 'remove' if args.remove else 'slim'
    freed, secrets = 0, 0

    for path in act:
        if args.remove:
            size = dir_size(path)
            files = None
        else:
            files = heavy_files(path)
            size = sum(os.path.getsize(f) for f in files if os.path.exists(f))
        keys = ' · holds TLS keys' if holds_secrets(path) else ''
        freed += size
        secrets += 1 if keys else 0
        print(f'  {verb} {path}  ({human(size)}{keys})')
        if not args.yes:
            continue
        if args.remove:
            shutil.rmtree(path, ignore_errors=True)
        else:
            for name in files:
                try:
                    os.remove(name)
                except OSError as exc:
                    print(f'    ! {name}: {exc}', file=sys.stderr)

    for path in spare:
        print(f'  spare {path}')

    print(f'\n{len(act)} run(s) to {verb}, {human(freed)}, '
          f'{secrets} holding TLS key material; {len(spare)} spared.')
    if not args.yes and act:
        # Say it plainly. A dry run that reads like a completed one is how a
        # cleanup script ends up trusted for work it never did.
        print('nothing was written — re-run with --yes to do it.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
