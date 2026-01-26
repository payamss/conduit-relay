#!/bin/bash
set -e

REPO="ssmirr/conduit"

CURRENT=$(/usr/local/bin/conduit --version 2>/dev/null | awk '{print $3}' || echo "none")
LATEST=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep -oP '"tag_name": "\K[^"]+')

echo "Current: $CURRENT"
echo "Latest:  $LATEST"

if [ "$CURRENT" = "$LATEST" ]; then
  echo "Already up to date."
  exit 0
fi

echo "Updating..."
curl -sL "https://github.com/$REPO/releases/download/$LATEST/conduit-linux-amd64" -o /usr/local/bin/conduit.new
chmod +x /usr/local/bin/conduit.new

systemctl stop conduit
mv /usr/local/bin/conduit.new /usr/local/bin/conduit
systemctl start conduit

echo "Updated to $LATEST"
