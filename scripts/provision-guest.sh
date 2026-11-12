#!/bin/sh
# Runs only INSIDE a disposable macOS guest, via its trusted setup account.
set -eu
case "$(/usr/sbin/sysctl -n hw.model)" in VirtualMac*) ;; *) echo 'guest required' >&2; exit 1;; esac
if ! /usr/bin/id iosagent >/dev/null 2>&1; then
  /usr/sbin/sysadminctl -addUser iosagent -fullName 'Build Worker' -shell /usr/bin/false -home /Users/iosagent -password "$1" >/dev/null 2>&1
fi
if [ ! -d /Users/iosagent ]; then
  /usr/sbin/createhomedir -c -u iosagent >/dev/null
fi
/usr/sbin/dseditgroup -o edit -d iosagent -t user admin >/dev/null 2>&1 || true
/usr/sbin/dseditgroup -o edit -a iosagent -t user _developer >/dev/null 2>&1 || true
/bin/chmod 700 /Users/iosagent
/bin/mkdir -p /Library/ios-worker/data/work /Library/ios-worker/data/spool /Library/ios-worker/data/artifacts /Library/ios-worker/data/tmp
/usr/sbin/chown -R iosagent:staff /Library/ios-worker/data
/bin/chmod 700 /Library/ios-worker/data /Library/ios-worker/data/*
/usr/sbin/chown -R root:wheel /Library/ios-worker/*.py /Library/ios-worker/worker.json
/bin/chmod 644 /Library/ios-worker/*.py /Library/ios-worker/worker.json
/bin/chmod 755 /Library/ios-worker
# The job account has no sudo grant. The trusted image admin is only a control
# account and is never used to run uploaded projects.
# Xcode setup is performed once by provision-tart.py before this account step.
# Reinstalling CoreSimulator during resume can invalidate runtime registration.
