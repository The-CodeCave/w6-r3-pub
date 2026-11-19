#!/bin/bash
# W6 security test helpers: the guest-side git route exactly as the hook writes it, plus HTTP checks. Never prints a token.
set -euo pipefail
CACHE=https://10.213.127.254
GIT_URL=$CACHE/git/github.com/
CA=$GITHUB_WORKSPACE/.w6/ca.pem
[ -f "$CA" ] || CA=$RUNNER_TEMP/w6-ca.pem
fails=0

route() {
  cat >"$RUNNER_TEMP/w6-cred.sh" <<'HELPER'
#!/bin/bash
[ "${1:-}" = --host ] && want=$2 && shift 2
[ "${1:-}" = get ] || { cat >/dev/null; exit 0; }
proto="" host="" path=""
while IFS= read -r l && [ -n "$l" ]; do case $l in protocol=*) proto=${l#protocol=};; host=*) host=${l#host=};; path=*) path=${l#path=};; esac; done
[ "$proto" = https ] && [ "$host" = "$want" ] || exit 0
path=${path#/}; path=${path#git/github.com/}
h=$(git config --get-urlmatch http.extraheader "https://github.com/$path" | grep -i '^authorization:' | tail -n1)
[[ $h =~ ^[Aa][Uu][Tt][Hh][Oo][Rr][Ii][Zz][Aa][Tt][Ii][Oo][Nn]:[[:space:]]*[Bb][Aa][Ss][Ii][Cc][[:space:]]+([^[:space:]]+) ]] || exit 0
p=$(base64 -d <<<"${BASH_REMATCH[1]}"); printf 'username=%s\npassword=%s\n' "${p%%:*}" "${p#*:}"
HELPER
  chmod 755 "$RUNNER_TEMP/w6-cred.sh"
  git config --global http."$GIT_URL".sslCAInfo "$CA"
  git config --global http."$GIT_URL".sslVerify true
  git config --global url."$GIT_URL".insteadOf https://github.com/
  git config --global url.https://github.com/.pushInsteadOf https://github.com/
  git config --global --add credential."$CACHE".helper ""
  git config --global --add credential."$CACHE".helper "$RUNNER_TEMP/w6-cred.sh --host 10.213.127.254"
  git config --global credential."$CACHE".useHttpPath true
}

# code method url [auth: token|forged|none] [body file] [content type]
code() {
  local m=$1 u=$2 a=${3:-none} body=${4:-} ct=${5:-application/x-git-upload-pack-request}
  local args=(-s -o "$RUNNER_TEMP/w6-body" -w '%{http_code}' --max-time 60 --cacert "$CA" -X "$m" -H "Git-Protocol: version=2")
  [ -n "$body" ] && args+=(--data-binary "@$body" -H "Content-Type: $ct")
  case $a in
  token) printf 'user = "x-access-token:%s"\n' "$TOKEN" | curl -K- "${args[@]}" "$u" ;;
  forged) curl "${args[@]}" -H "Authorization: Bearer gcp2.9999999999.AAAA" "$u" ;;
  *) curl "${args[@]}" "$u" ;;
  esac
}

check() { # name got want-regex
  if [[ $2 =~ ^($3)$ ]]; then echo "PASS $1 ($2)"; else echo "FAIL $1: got $2, want $3"; fails=$((fails + 1)); fi
}

body_lacks() { # name needle
  if grep -qF "$2" "$RUNNER_TEMP/w6-body"; then echo "FAIL $1: response contains $2"; fails=$((fails + 1)); else echo "PASS $1 (absent)"; fi
}

body_has() { # name needle
  if grep -qF "$2" "$RUNNER_TEMP/w6-body"; then echo "PASS $1 (present)"; else echo "FAIL $1: response lacks $2"; fails=$((fails + 1)); fi
}

ls_refs_body() {
  local pkt f=$RUNNER_TEMP/w6-lsrefs
  pkt() { printf '%04x%s' $((${#1} + 4)) "$1"; }
  { pkt $'command=ls-refs\n'; printf 0001; pkt $'peel\n'; pkt $'symrefs\n'; printf 0000; } >"$f"
  echo "$f"
}

lfs_body() { # oid size
  local f=$RUNNER_TEMP/w6-lfs
  printf '{"operation":"download","transfers":["basic"],"objects":[{"oid":"%s","size":%s}]}' "$1" "$2" >"$f"
  echo "$f"
}

# hcode method url header [body file] [content type]: like code, with one explicit header (a grant), never a token.
hcode() {
  local m=$1 u=$2 h=$3 body=${4:-} ct=${5:-application/x-git-upload-pack-request}
  local args=(-s -o "$RUNNER_TEMP/w6-body" -w '%{http_code}' --max-time 60 --cacert "$CA" -X "$m")
  [ -n "$h" ] && args+=(-H "$h")
  [ -n "$body" ] && args+=(--data-binary "@$body" -H "Content-Type: $ct")
  curl "${args[@]}" "$u"
}

fetch_body() { # want-sha
  local pkt f=$RUNNER_TEMP/w6-fetch
  pkt() { printf '%04x%s' $((${#1} + 4)) "$1"; }
  { pkt $'command=fetch\n'; printf 0001; pkt "want $1"$'\n'; pkt $'done\n'; printf 0000; } >"$f"
  echo "$f"
}

stamp() { date -u +%H:%M:%S; }

done_checks() { echo "result: $fails failed"; [ "$fails" = 0 ]; }
