#!/bin/zsh
# Run wkfido. The JSON result goes to stdout; the APDU trace goes to stderr.
#   ./run.sh create example.com --rk
# WKFIDO_SYSLOG=1 also captures WebKit's and CryptoTokenKit's own log lines.
here=${0:a:h}
if [[ -z $WKFIDO_SYSLOG ]]; then
    exec "$here/wkfido" "$@"
fi
log=$(mktemp -t wkfido-log)
/usr/bin/log stream --level debug --style compact \
    --predicate 'process == "wkfido" AND (category == "WebAuthn" OR subsystem == "com.apple.CryptoTokenKit")' \
    > "$log" 2>&1 &
logpid=$!
sleep 1
"$here/wkfido" "$@"
rc=$?
sleep 0.5
kill $logpid 2>/dev/null
{
    echo "--- system log ---"
    ag 'WebAuthn|connected to slot|error' "$log" | cut -c1-220
} >&2
rm -f "$log"
exit $rc
