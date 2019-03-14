#!/bin/bash

TOPDIR=${TOPDIR:-$(git rev-parse --show-toplevel)}
SRCDIR=${SRCDIR:-$TOPDIR/src}
MANDIR=${MANDIR:-$TOPDIR/doc/man}

NOTECOIND=${NOTECOIND:-$SRCDIR/notecoind}
NOTECOINCLI=${NOTECOINCLI:-$SRCDIR/notecoin-cli}
NOTECOINTX=${NOTECOINTX:-$SRCDIR/notecoin-tx}
NOTECOINQT=${NOTECOINQT:-$SRCDIR/qt/notecoin-qt}

[ ! -x $NOTECOIND ] && echo "$NOTECOIND not found or not executable." && exit 1

# The autodetected version git tag can screw up manpage output a little bit
NOTESVER=($($NOTECOINCLI --version | head -n1 | awk -F'[ -]' '{ print $6, $7 }'))

# Create a footer file with copyright content.
# This gets autodetected fine for bitcoind if --version-string is not set,
# but has different outcomes for bitcoin-qt and bitcoin-cli.
echo "[COPYRIGHT]" > footer.h2m
$NOTECOIND --version | sed -n '1!p' >> footer.h2m

for cmd in $NOTECOIND $NOTECOINCLI $NOTECOINTX $NOTECOINQT; do
  cmdname="${cmd##*/}"
  help2man -N --version-string=${NOTESVER[0]} --include=footer.h2m -o ${MANDIR}/${cmdname}.1 ${cmd}
  sed -i "s/\\\-${NOTESVER[1]}//g" ${MANDIR}/${cmdname}.1
done

rm -f footer.h2m
