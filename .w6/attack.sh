#!/bin/bash
# W6 round 3: a token that may only read its own public repo against a warm private mirror (git v2, LFS, SHA fetch, grant and
# auth-cache reuse), and as a fork-PR token trying to push or seed a mirror. Never prints a token or a grant.
# env: MODE (public|fork), T (private path owner/repo), XSHA, XOID, XSIZE, SECONDS_ (loop length), TOKEN, OWN_OID, OWN_SIZE
set -uo pipefail
. "$RUNNER_TEMP/w6-route.sh"
own=$GITHUB_REPOSITORY
echo "repo $own (mode $MODE), target $T, start $(stamp)"

# Controls: the cache works for this token on its own repo.
check "own repo info/refs" "$(code GET "${GIT_URL}$own/info/refs?service=git-upload-pack" token)" 200
check "own LFS batch" "$(code POST "${GIT_URL}$own.git/info/lfs/objects/batch" token "$(lfs_body "$OWN_OID" "$OWN_SIZE")" application/vnd.git-lfs+json)" 200
href=$(jq -r '.objects[0].actions.download.href // ""' "$RUNNER_TEMP/w6-body")
grant=$(jq -r '.objects[0].actions.download.header.Authorization // ""' "$RUNNER_TEMP/w6-body")
granted=$(date +%s)
check "own object with its own grant" "$(hcode GET "$href" "Authorization: $grant")" 200
check "own object content" "$(sha256sum "$RUNNER_TEMP/w6-body" | cut -c1-64)" "$OWN_OID"

# Grant reuse within its 60 s: a valid grant for our object never opens the private object, under any path.
for p in "$T.git" "$own.git"; do
  check "own grant on the private object under $p" "$(hcode GET "${GIT_URL}$p/info/lfs/objects/$XOID?size=$XSIZE" "Authorization: $grant")" '401|404'
  body_lacks "own grant, $p: no private content" "W6-R3-LFS-SECRET"
done
check "own grant on own object under the private path" "$(hcode GET "${GIT_URL}$T.git/info/lfs/objects/$OWN_OID?size=$OWN_SIZE" "Authorization: $grant")" '401|404'
check "forged grant on the private object" "$(code GET "${GIT_URL}$T.git/info/lfs/objects/$XOID?size=$XSIZE" forged)" '401|404'
check "no credential on the private object" "$(code GET "${GIT_URL}$T.git/info/lfs/objects/$XOID?size=$XSIZE")" '401|404'

# The victim keeps the private mirror warm and its verdicts cached (30 s) meanwhile: every round must still be refused.
rounds=0 bad=0
end=$(($(date +%s) + SECONDS_))
while [ "$(date +%s)" -lt "$end" ]; do
  rounds=$((rounds + 1)) r=""
  c=$(code GET "${GIT_URL}$T/info/refs?service=git-upload-pack" token); r+="info/refs=$c "
  { [ "$c" = 401 ] && ! grep -qF "$XSHA" "$RUNNER_TEMP/w6-body"; } || bad=$((bad + 1))
  c=$(code POST "${GIT_URL}$T/git-upload-pack" token "$(ls_refs_body)"); r+="ls-refs=$c "
  { [ "$c" = 401 ] && ! grep -qF "$XSHA" "$RUNNER_TEMP/w6-body"; } || bad=$((bad + 1))
  c=$(code POST "${GIT_URL}$T/git-upload-pack" token "$(fetch_body "$XSHA")"); r+="fetch-by-sha=$c "
  { [ "$c" = 401 ] && ! grep -q PACK "$RUNNER_TEMP/w6-body"; } || bad=$((bad + 1))
  # The private commit asked for under our own public path: GitHub has it in no network of ours, so nothing comes back.
  c=$(code POST "${GIT_URL}$own/git-upload-pack" token "$(fetch_body "$XSHA")"); r+="own-path-fetch=$c "
  ! grep -q PACK "$RUNNER_TEMP/w6-body" || bad=$((bad + 1))
  c=$(code POST "${GIT_URL}$T.git/info/lfs/objects/batch" token "$(lfs_body "$XOID" "$XSIZE")" application/vnd.git-lfs+json); r+="lfs-batch=$c "
  { [ "$c" = 401 ] && ! grep -qF '"download"' "$RUNNER_TEMP/w6-body"; } || bad=$((bad + 1))
  c=$(hcode GET "${GIT_URL}$T.git/info/lfs/objects/$XOID?size=$XSIZE" "Authorization: $grant"); r+="lfs-object=$c"
  { [[ $c =~ ^40[14]$ ]] && ! grep -qF "W6-R3-LFS-SECRET" "$RUNNER_TEMP/w6-body"; } || bad=$((bad + 1))
  echo "$(stamp) round $rounds: $r"
  sleep 5
done
check "every round refused ($rounds rounds over ${SECONDS_} s)" "$bad" 0

# git itself, through the route: the private repo and its commit stay out of reach.
check "git ls-remote of the private repo" "$(GIT_TERMINAL_PROMPT=0 git ls-remote "https://github.com/$T" >/dev/null 2>&1 && echo listed || echo refused)" refused
git init -q "$RUNNER_TEMP/w6-probe" && git -C "$RUNNER_TEMP/w6-probe" remote add origin "https://github.com/$T"
check "git fetch of the private commit by SHA" "$(GIT_TERMINAL_PROMPT=0 git -C "$RUNNER_TEMP/w6-probe" fetch -q origin "$XSHA" >/dev/null 2>&1 && echo fetched || echo refused)" refused

for e in metrics readyz healthz; do check "ops endpoint $e with a real token" "$(code GET "${GIT_URL}$e" token)" 404; done

if [ "$MODE" = fork ]; then
  # Fork-PR token: read-only for the base repo, no way into the cache's write side or another repo's mirror.
  check "receive-pack advertisement through the cache" "$(code GET "${GIT_URL}$own/info/refs?service=git-receive-pack" token)" 404
  check "receive-pack POST through the cache" "$(code POST "${GIT_URL}$own/git-receive-pack" token "$(ls_refs_body)")" 404
  check "push (pushInsteadOf: straight to github.com)" "$(GIT_TERMINAL_PROMPT=0 git push -q origin HEAD:refs/heads/w6-fork-push >/dev/null 2>&1 && echo pushed || echo refused)" refused
  # Outside the window's three-repo allowlist: nginx answers 404 before git-cache-proxy (which would answer 401) is reached.
  check "seed a mirror for a repo that does not exist" "$(code GET "${GIT_URL}The-CodeCave/w6-r3-doesnotexist/info/refs?service=git-upload-pack" token)" 404
  check "seed the private path" "$(code POST "${GIT_URL}$T/git-upload-pack" token "$(ls_refs_body)")" 401
  # The PR head commit lives in the fork; GitHub serves it under the base repo (refs/pull/N/head). Fetching it by SHA through the
  # cache may pin it under the mirror's hidden namespace, never under a branch: the advertised branches stay GitHub's.
  c=$(code POST "${GIT_URL}$own/git-upload-pack" token "$(fetch_body "$FORK_SHA")")
  echo "fork head $FORK_SHA by SHA through the cache: $c"
  via=$(git ls-remote "https://github.com/$own" 'refs/heads/*' | sort)
  direct=$(GIT_CONFIG_GLOBAL=/dev/null git ls-remote "https://github.com/$own" 'refs/heads/*' 2>/dev/null | sort)
  check "branches through the cache equal github.com's" "$([ -n "$via" ] && [ "$via" = "$direct" ] && echo equal || echo differ)" equal
  check "fork head is not a branch of the mirror" "$(grep -q "$FORK_SHA" <<<"$via" && echo advertised || echo hidden)" hidden
fi

# Past the grant's 60 s: our own grant is dead too.
wait_s=$((granted + 65 - $(date +%s)))
[ "$wait_s" -gt 0 ] && sleep "$wait_s"
check "own grant after 65 s" "$(hcode GET "$href" "Authorization: $grant")" '401|404'
echo "end $(stamp)"
done_checks
