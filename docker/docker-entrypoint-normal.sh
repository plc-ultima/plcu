#!/bin/sh
set -e

if [ $(echo "$1" | cut -c1) = "-" ]; then
    echo "$0: assuming arguments for plcultimad"
    
    set -- plcultimad "$@"
fi

if [ $(echo "$1" | cut -c1) = "-" ] || [ "$1" = "plcultimad" ]; then
    mkdir -p "$PLCULTIMA_DATA"
    chmod 770 "$PLCULTIMA_DATA" || echo "Could notchmod $PLCULTIMA_DATA (may not have appropriate permissions)"
    
    echo "$0: setting data directory to $PLCULTIMA_DATA"
    
    set -- "$@" -datadir="$PLCULTIMA_DATA"
fi

exec "$@"
