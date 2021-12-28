#!/bin/bash
set -e

ZMQ_PORT=9331
RPC_PORT=9332
HEALTH_PORT=9333
RPC_AUTH="$(echo -n "$PLCULTIMA_RPC_USERNAME:$PLCULTIMA_RPC_PASSWORD" | base64)"

# PLCULTIMA_BLOCKS_URI="${PLCULTIMA_BLOCKS_URI:-https://cdn.plcultima.com/db/blockchain}"

export RPC_AUTH
export HEALTH_PORT
export RPC_PORT

if [ -n "$PLCULTIMA_TESTNET" ]; then
  echo "Initializing TESTNET"
  set -- "$@" -testnet=1
  BLOCKCHAIN_FILE="test.tgz"
else
  echo "Initializing MAINNET"
  set -- "$@" -testnet=0  
  BLOCKCHAIN_FILE="main.tgz"
fi

echo "Starting nginx"
/bin/bash -c "envsubst < /etc/nginx/health.template > /etc/nginx/sites-available/default && nginx"

set -- "$@" -printtoconsole -conf=/etc/plcultima.conf
set -- "$@" -rpcuser="$PLCULTIMA_RPC_USERNAME"
set -- "$@" -rpcpassword="$PLCULTIMA_RPC_PASSWORD"

if [ -n "$PLCULTIMA_ZMQ_ENABLED" ]; then
  echo "ZMQ enabled, starting on port $ZMQ_PORT"
  set -- "$@" -zmqpubjsontx=tcp://0.0.0.0:"$ZMQ_PORT"
  set -- "$@" -zmqpubjsonfullblock=tcp://0.0.0.0:"$ZMQ_PORT"
else
  echo "ZMQ disabled, not starting"
fi

download_blocks=0
if [ -n "$PLCULTIMA_BLOCKS_URI" ]; then
  if [ ! -d "$PLCULTIMA_DATA/blocks" ]; then
      download_blocks=1
      echo "No blocks found in $PLCULTIMA_DATA/blocks, downloading from $PLCULTIMA_BLOCKS_URI/$BLOCKCHAIN_FILE..."
  elif [ -n "$PLCULTIMA_FORCE_BLOCKS_DOWNLOAD" ]; then
      download_blocks=1
      echo "Forcing block updates from $PLCULTIMA_BLOCKS_URI..."
  else
      echo "Blocks found in $PLCULTIMA_DATA/blocks, no download."
  fi

  if [ $download_blocks -eq 1 ]; then
      md5remote=$(/usr/bin/wget -q -c -O - "$PLCULTIMA_BLOCKS_URI/${BLOCKCHAIN_FILE}.md5" | cut -d' ' -f1)
      if ! /usr/bin/wget -q -c -O - "$PLCULTIMA_BLOCKS_URI/$BLOCKCHAIN_FILE"| tee >(md5sum>${BLOCKCHAIN_FILE}.md5) | tar zxf - -C "$PLCULTIMA_DATA"/.. ; then
          echo "Download failed."
          exit 1
      else
          md5local=$(cat "${BLOCKCHAIN_FILE}.md5" | cut -d' ' -f1)
          if [ "x$md5local" != "x$md5remote" ] ; then
            echo "Invalid checksum. Download failed."
            exit 1
          else
            echo "Download complete."
          fi
      fi
  fi
fi

if [ $(echo "$1" | cut -c1) = "-" ] || [ "$1" = "plcultimad" ]; then
  chmod 770 "$PLCULTIMA_DATA" || echo "Could not chmod $PLCULTIMA_DATA (may not have appropriate permissions)"
  echo "Setting data directory to $PLCULTIMA_DATA."
  set -- "$@" -datadir="$PLCULTIMA_DATA"
fi

if [ $(echo "$1" | cut -c1) = "-" ]; then
  echo "Taking CLI arguments for plcultimad"
  set -- plcultimad "$@"
fi

echo "Starting node with arguments " "$@"
exec "$@"