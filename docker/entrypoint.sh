#!/bin/sh
# Dashboard entrypoint script
# Runs as root to copy SSH keys, then drops to node user

SSH_SOURCE="/ssh/id_ed25519"
SSH_DIR="/home/node/.ssh"
SSH_KEY="$SSH_DIR/id_ed25519"

# Create .ssh directory
mkdir -p "$SSH_DIR"

# Copy SSH key if source exists
if [ -f "$SSH_SOURCE" ]; then
  cp "$SSH_SOURCE" "$SSH_KEY"
  chmod 600 "$SSH_KEY"
  chown node:node "$SSH_KEY"

  # Copy public key if exists
  if [ -f "${SSH_SOURCE}.pub" ]; then
    cp "${SSH_SOURCE}.pub" "${SSH_KEY}.pub"
    chmod 644 "${SSH_KEY}.pub"
    chown node:node "${SSH_KEY}.pub"
  fi

  export SSH_KEY_PATH="$SSH_KEY"
else
  echo "Warning: SSH key not found at $SSH_SOURCE"
  echo "Remote server monitoring will not work."
fi

# Ensure data directory is owned by node
chown -R node:node /opt/conduit-dashboard/data 2>/dev/null || true

# Drop to node user and run server
exec su-exec node node server.js
