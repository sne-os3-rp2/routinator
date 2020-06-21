#!/bin/sh
set -e
user=routinator
repo="$IPFS_PATH"

if [ -e "$repo/config" ]; then
  echo "Found IPFS fs-repo at $repo"
else
  case "$IPFS_PROFILE" in
    "") INIT_ARGS="" ;;
    *) INIT_ARGS="--profile=badgerds" ;;
  esac
  ipfs init $INIT_ARGS
  ipfs config Addresses.API /ip4/0.0.0.0/tcp/5001
  ipfs config Addresses.Gateway /ip4/0.0.0.0/tcp/8080

# Set up the swarm key, if provided

  SWARM_KEY_FILE="$repo/swarm.key"
  SWARM_KEY_PERM=0400

  # Create a swarm key from a given environment variable
  if [ ! -z "$IPFS_SWARM_KEY" ] ; then
    echo "Copying swarm key from variable..."
    echo -e "$IPFS_SWARM_KEY" >"$SWARM_KEY_FILE" || exit 1
    chmod $SWARM_KEY_PERM "$SWARM_KEY_FILE"
  fi

  # Unset the swarm key variable
  unset IPFS_SWARM_KEY

  # Check during initialization if a swarm key was provided and
  # copy it to the ipfs directory with the right permissions
  # WARNING: This will replace the swarm key if it exists
  if [ ! -z "$IPFS_SWARM_KEY_FILE" ] ; then
    echo "Copying swarm key from file..."
    install -m $SWARM_KEY_PERM "$IPFS_SWARM_KEY_FILE" "$SWARM_KEY_FILE" || exit 1
  fi

  # Unset the swarm key file variable
  unset IPFS_SWARM_KEY_FILE

fi

# Second guard rail to ensure a private network
ipfs bootstrap rm --all


echo "Running as $(whoami)"


if [ ! -z "$IS_BOOTNODE" ] ; then
     echo "Copying peer id of boot node..."
     PEER_ID=$(ipfs id | grep "ID" | cut -d ':' -f 2 | sed 's/.$//' | tr -d '"' | tr -d " ")
     echo "Peer ID ${PEER_ID} generated"
     cat /dev/null > /usr/local/nexus/peerid
     echo $PEER_ID > /usr/local/nexus/peerid
     echo "Saved peer ID of bootnode as:"
     echo $(cat /usr/local/nexus/peerid)
else
     PEER_ID=$(cat /usr/local/nexus/peerid)
     echo "Reading peer id ${PEER_ID} of boot node..."
fi

ipfs bootstrap add /ip4/${BOOTNODE_IP}/tcp/4001/ipfs/${PEER_ID}

ipfs daemon --migrate=true &

# force to start in private network
#export LIBP2P_FORCE_PNET=1

exec routinator "$@"