#!/bin/sh
# Runs all the tests of the net package. With --online, http_test also
# uses the internet.
#
#   ./run_tests.sh [--online]
#
# goose writes its progress to stderr. The script shows that output only
# when a step fails.

cd "$(dirname "$0")/test" || exit 1
tmp="${TMPDIR:-/tmp}"
log="$tmp/goose_net_test.log"
# The large compress cases are not in git. Make them if Python is here.
if [ ! -d data/gen ]; then
    for py in python3 python; do
        if command -v "$py" > /dev/null 2>&1; then "$py" -I make_fixtures.py && break; fi
    done
fi
for t in url_test cookie_test compress_test net_test; do
    goose "$t.goose" 2> "$log" || { cat "$log"; exit 1; }
done
goose build -o "$tmp/goose_net_http_test" http_test.goose > "$log" 2>&1 || { cat "$log"; exit 1; }
"$tmp/goose_net_http_test" "$@"
