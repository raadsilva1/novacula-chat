#!/usr/bin/env bash
set -euo pipefail

IMAGE="ghcr.io/void-linux/void-glibc-full:latest"
TASK="novacula-chat-build"

if ! command -v ctr >/dev/null 2>&1; then
  echo "ctr not found"
  exit 1
fi

ctr images pull "${IMAGE}"

ctr run --rm --net-host \
  --mount "type=bind,src=$(pwd),dst=/src,options=rbind:ro" \
  "${IMAGE}" "${TASK}" \
  sh -lc '
    set -eu
    export LC_ALL=C
    export LANG=C

    # Force "fastest" repo (Fastly CDN) for xbps
    mkdir -p /etc/xbps.d
    cp -f /usr/share/xbps.d/*repository*.conf /etc/xbps.d/ 2>/dev/null || true
    if ls /etc/xbps.d/*repository*.conf >/dev/null 2>&1; then
      sed -i "s|https://repo-default.voidlinux.org|https://repo-fastly.voidlinux.org|g" /etc/xbps.d/*repository*.conf || true
      sed -i "s|http://repo-default.voidlinux.org|https://repo-fastly.voidlinux.org|g" /etc/xbps.d/*repository*.conf || true
    else
      printf "repository=https://repo-fastly.voidlinux.org/current\n" > /etc/xbps.d/00-repository-main.conf
    fi

    xbps-install -Sy -y perl openssl curl ca-certificates tzdata

    mkdir -p /opt/novacula-chat
    cp -a /src/* /opt/novacula-chat/
    cd /opt/novacula-chat

    perl -c novacula-chat.pl
    perl -c test-client.pl
  '

echo "OK"
