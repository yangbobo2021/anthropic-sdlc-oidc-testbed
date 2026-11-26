#!/usr/bin/env bash
set -euo pipefail
umask 077
scratch="$(mktemp -d)"
bao_pid=''
cleanup() {
  if [[ -n "$bao_pid" ]]; then kill "$bao_pid" 2>/dev/null || true; fi
  rm -rf -- "$scratch"
}
trap cleanup EXIT

curl -fsSL --retry 2 https://github.com/openbao/openbao/releases/download/v2.4.1/bao_2.4.1_linux_amd64.deb -o "$scratch/bao.deb"
printf '%s  %s\n' 599605411c617efe6855874e22e5e7bb0cef75d335afdef2f92d83c8e3aff471 "$scratch/bao.deb" | sha256sum -c
dpkg-deb -x "$scratch/bao.deb" "$scratch/bao"
bao="$scratch/bao/usr/bin/bao"
export BAO_ADDR=http://127.0.0.1:18200
export BAO_TOKEN
BAO_TOKEN="$(openssl rand -hex 32)"
BAO_DEV_ROOT_TOKEN_ID="$BAO_TOKEN" "$bao" server -dev -dev-listen-address=127.0.0.1:18200 > "$scratch/server.log" 2>&1 &
bao_pid=$!
curl -fsS --retry 8 --retry-connrefused "$BAO_ADDR/v1/sys/health" > /dev/null
"$bao" version
"$bao" auth enable jwt > /dev/null
"$bao" write auth/jwt/config oidc_discovery_url=https://token.actions.githubusercontent.com bound_issuer=https://token.actions.githubusercontent.com > /dev/null
python3 probe/evaluate.py
