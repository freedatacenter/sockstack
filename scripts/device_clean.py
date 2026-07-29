#!/usr/bin/env python3
"""device_clean.py — uninstall the apps an analysis device collects.

A stand accumulates samples. That is worse than untidy: the capture is
device-wide, so anything still installed and still running turns up in every
later run as traffic nobody can attribute, and a sample with a background
service keeps talking to its C2 from your lab long after you stopped studying
it. Removing what you are no longer working on is part of keeping results
readable.

Only third-party packages are ever considered — `pm list packages -3`. System
and vendor packages are not this script's business, and a device that will not
boot is a worse outcome than a cluttered one.

Nothing is uninstalled without naming it, and nothing at all happens without
`--yes`:

    ./scripts/device_clean.py --device emulator-5554
    ./scripts/device_clean.py --device emulator-5554 --remove com.example.a --yes
    ./scripts/device_clean.py --device emulator-5554 --remove-all \\
        --keep ru.example.keepme --yes
"""
import argparse
import os
import subprocess
import sys

TIMEOUT = 60


def adb(serial, *args, timeout=TIMEOUT):
    cmd = ['adb']
    if serial:
        cmd += ['-s', serial]
    return subprocess.run(cmd + list(args), capture_output=True, text=True,
                          timeout=timeout)


def parse_listing(text):
    """`pm list packages -3 -U -i` -> [{name, installer, uid}].

    The installer matters when deciding what is safe to lose: `installer=null`
    is something that was pushed here by hand, which on an analysis device means
    a sample or a tool. Anything with a real installer arrived by another route
    and is more likely to be part of the image someone set up deliberately.
    """
    packages = []
    for line in (text or '').replace('\r', '').splitlines():
        line = line.strip()
        if not line.startswith('package:'):
            continue
        fields = line[len('package:'):].split()
        if not fields:
            continue
        entry = {'name': fields[0], 'installer': '', 'uid': ''}
        for field in fields[1:]:
            if field.startswith('installer='):
                value = field[len('installer='):]
                entry['installer'] = '' if value == 'null' else value
            elif field.startswith('uid:'):
                entry['uid'] = field[len('uid:'):]
        packages.append(entry)
    return sorted(packages, key=lambda p: p['name'])


def choose(packages, remove, keep, remove_all):
    """(to_remove, skipped_because_named_to_keep, asked_for_but_absent).

    Named packages win over `--remove-all`, and `--keep` wins over everything.
    A cleanup that can be talked into removing the one thing you protected is
    not one you can run without reading the output every time.
    """
    names = {p['name'] for p in packages}
    keep = set(keep or ())
    asked = set(remove or ())
    missing = sorted(asked - names)
    if remove_all:
        wanted = names - keep
    else:
        wanted = (asked & names) - keep
    spared = sorted((asked & names & keep) | (keep & names if remove_all else set()))
    return sorted(wanted), spared, missing


def install_time(serial, package):
    out = adb(serial, 'shell', f'dumpsys package {package} | grep -m1 firstInstallTime')
    text = (out.stdout or '').replace('\r', '').strip()
    return text.split('=', 1)[1].strip() if '=' in text else ''


def uninstall(serial, package):
    """(ok, detail). Reports rather than escalates.

    An updated system app cannot be removed this way, only reverted per user,
    and doing that silently would be this script quietly doing something other
    than what it said.
    """
    out = adb(serial, 'uninstall', package)
    text = ((out.stdout or '') + (out.stderr or '')).replace('\r', '').strip()
    return text.startswith('Success'), text or 'adb said nothing'


def main(argv=None):
    ap = argparse.ArgumentParser(
        description='List and uninstall third-party apps on an analysis device.')
    ap.add_argument('--device', default=os.environ.get('ANDROID_SERIAL', ''),
                    help='adb device id (default: $ANDROID_SERIAL)')
    ap.add_argument('--remove', nargs='*', default=[], metavar='PKG',
                    help='packages to uninstall')
    ap.add_argument('--remove-all', action='store_true',
                    help='uninstall every third-party package except --keep')
    ap.add_argument('--keep', nargs='*', default=[], metavar='PKG',
                    help='never uninstall these')
    ap.add_argument('--yes', action='store_true',
                    help='actually uninstall; without this nothing is changed')
    args = ap.parse_args(argv)

    listing = adb(args.device, 'shell', 'pm list packages -3 -U -i')
    if listing.returncode != 0:
        print(f'[!] could not list packages: {(listing.stderr or "").strip()[:200]}',
              file=sys.stderr)
        return 2
    packages = parse_listing(listing.stdout)
    if not packages:
        print('no third-party packages on this device')
        return 0

    wanted, spared, missing = choose(packages, args.remove, args.keep,
                                     args.remove_all)
    for entry in packages:
        mark = 'REMOVE' if entry['name'] in wanted else '      '
        source = entry['installer'] or 'sideloaded'
        when = install_time(args.device, entry['name'])
        print(f'  {mark} {entry["name"]:<34} uid {entry["uid"]:<7} {source:<22} {when}')

    for name in spared:
        print(f'  kept   {name} (named in --keep)')
    for name in missing:
        print(f'  ?      {name} is not installed on this device')

    if not wanted:
        print('\nnothing selected — name packages with --remove, or --remove-all.')
        return 0
    if not args.yes:
        print(f'\n{len(wanted)} package(s) would be uninstalled. '
              f'Nothing was changed — re-run with --yes.')
        return 0

    failed = 0
    for name in wanted:
        ok, detail = uninstall(args.device, name)
        print(f'  {"removed" if ok else "FAILED "} {name}'
              f'{"" if ok else "  — " + detail}')
        failed += 0 if ok else 1
    print(f'\n{len(wanted) - failed} removed, {failed} failed.')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
