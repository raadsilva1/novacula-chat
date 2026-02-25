#!/usr/bin/env bash
set -euo pipefail

IMAGE="ghcr.io/void-linux/void-glibc-full:latest"
NAME="novacula-chat"

MODE="default"
SERVER_ARGS=()

# args:
#   --production
#   --cors [origins]
#   --do-not-check-ig
while [[ $# -gt 0 ]]; do
  case "$1" in
    --production)
      MODE="production"
      shift
      ;;
    --cors)
      SERVER_ARGS+=("--cors")
      shift
      if [[ $# -gt 0 && "$1" != --* ]]; then
        SERVER_ARGS+=("$1")
        shift
      fi
      ;;
    --do-not-check-ig)
      SERVER_ARGS+=("--do-not-check-ig")
      shift
      ;;
    *)
      echo "Usage: $0 [--production] [--cors [ORIGINS]] [--do-not-check-ig]" >&2
      exit 1
      ;;
  esac
done

if ! command -v ctr >/dev/null 2>&1; then
  echo "ctr not found" >&2
  exit 1
fi

: "${NOVACULA_AUTH_SECRET:?missing NOVACULA_AUTH_SECRET}"
: "${NOVACULA_CHAT_KEY:?missing NOVACULA_CHAT_KEY}"

mkdir -p "$(pwd)/data"

ctr images pull "${IMAGE}"

# best-effort cleanup
ctr tasks kill -s SIGKILL "${NAME}" >/dev/null 2>&1 || true
ctr tasks rm "${NAME}" >/dev/null 2>&1 || true
ctr containers rm "${NAME}" >/dev/null 2>&1 || true

XBPS_REPO_MAIN="https://repo-fastly.voidlinux.org/current"

if [[ "${MODE}" != "production" ]]; then
  ctr run --rm --net-host \
    --env "NOVACULA_AUTH_SECRET=${NOVACULA_AUTH_SECRET}" \
    --env "NOVACULA_CHAT_KEY=${NOVACULA_CHAT_KEY}" \
    --env "NOVACULA_DEBUG_WS=${NOVACULA_DEBUG_WS:-}" \
    --env "NOVACULA_DEBUG_IG=${NOVACULA_DEBUG_IG:-}" \
    --mount "type=bind,src=$(pwd),dst=/src,options=rbind:ro" \
    --mount "type=bind,src=$(pwd)/data,dst=/var/lib/novacula-chat,options=rbind:rw" \
    "${IMAGE}" "${NAME}" \
    sh -lc '
      set -eu
      export LC_ALL=C
      export LANG=C

      xbps-install -Sy -y -R "'"${XBPS_REPO_MAIN}"'" perl openssl curl ca-certificates tzdata

      mkdir -p /opt/novacula-chat
      cp -a /src/* /opt/novacula-chat/
      cd /opt/novacula-chat

      exec perl /opt/novacula-chat/novacula-chat.pl "$@"
    ' -- "${SERVER_ARGS[@]}"
  exit 0
fi

LOGFILE="$(pwd)/data/novacula-chat.production.log"
MEM_LIMIT_BYTES=$((400 * 1024 * 1024))

MEM_ARGS=()
CGROUP_NAME=""

if ctr run --help 2>&1 | grep -q -- '--memory-limit'; then
  MEM_ARGS+=(--memory-limit "${MEM_LIMIT_BYTES}")
elif ctr run --help 2>&1 | grep -q -- '--cgroup'; then
  CGROUP_NAME="novacula-chat-prod"
  MEM_ARGS+=(--cgroup "${CGROUP_NAME}")
fi

nohup ctr run --net-host \
  "${MEM_ARGS[@]}" \
  --env "NOVACULA_AUTH_SECRET=${NOVACULA_AUTH_SECRET}" \
  --env "NOVACULA_CHAT_KEY=${NOVACULA_CHAT_KEY}" \
  --env "NOVACULA_DEBUG_WS=${NOVACULA_DEBUG_WS:-}" \
  --env "NOVACULA_DEBUG_IG=${NOVACULA_DEBUG_IG:-}" \
  --mount "type=bind,src=$(pwd)/novacula-chat.pl,dst=/novacula-chat.pl,options=rbind:ro" \
  --mount "type=bind,src=$(pwd)/data,dst=/var/lib/novacula-chat,options=rbind:rw" \
  --mount "type=tmpfs,dst=/tmp,options=nosuid:nodev:noexec" \
  --mount "type=tmpfs,dst=/run,options=nosuid:nodev" \
  "${IMAGE}" "${NAME}" \
  sh -lc '
    set -eu
    export LC_ALL=C
    export LANG=C

    xbps-install -Sy -y -R "'"${XBPS_REPO_MAIN}"'" perl openssl curl ca-certificates tzdata

    mkdir -p /var/lib/novacula-chat
    exec perl /novacula-chat.pl "$@"
  ' -- "${SERVER_ARGS[@]}" \
  >"${LOGFILE}" 2>&1 &

disown || true

if [[ -n "${CGROUP_NAME}" ]]; then
  if [[ -f "/sys/fs/cgroup/${CGROUP_NAME}/memory.max" ]]; then
    echo "${MEM_LIMIT_BYTES}" > "/sys/fs/cgroup/${CGROUP_NAME}/memory.max" 2>/dev/null || true
  elif [[ -f "/sys/fs/cgroup/${CGROUP_NAME}/memory.limit_in_bytes" ]]; then
    echo "${MEM_LIMIT_BYTES}" > "/sys/fs/cgroup/${CGROUP_NAME}/memory.limit_in_bytes" 2>/dev/null || true
  fi
fi

echo "Started ${NAME} in --production mode (detached)."
echo "Log: ${LOGFILE}"
echo "Stop:"
echo "  ctr tasks kill -s SIGKILL ${NAME} || true"
echo "  ctr tasks rm ${NAME} || true"
echo "  ctr containers rm ${NAME} || true"
