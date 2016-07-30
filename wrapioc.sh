#!/bin/sh
set -e

die() {
    echo "$1" >&2
    exit 1
}

[ "$WRAPDEBUG" ] && set -x

[ -x "$SOFTIOC" ] || die "Must set \$SOFTIOC to softIoc executable"

BASE="$(mktemp -d)"

trap "rm -rf '$BASE'" TERM KILL HUP QUIT EXIT

cd "$BASE"

cat <<EOF > test.db
record(longout, "ival") {
    field(VAL, "42")
}
record(waveform, "aval") {
    field(FTVL, "SHORT")
    field(NELM, "5")
}
EOF

"$SOFTIOC" -d test.db
