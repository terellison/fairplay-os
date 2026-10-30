#!/usr/bin/env bash
# Print a GitHub token for the fairplay-os agents' GitHub App, scoped to this
# repository and valid for one hour. Agents push, open PRs and comment as the
# App, never as a person, so a human's approval is a real second identity and
# branch protection can require it.
#
#   export GH_TOKEN="$(tools/gh-app-token.sh)"     # then gh / git as the App
#
# Config (not in git): ~/.config/fairplay-agents/app.env, overridable with
# FAIRPLAY_AGENT_ENV, defining FAIRPLAY_APP_ID, FAIRPLAY_APP_KEY (path to the
# App's private key) and FAIRPLAY_REPO (owner/name).
set -euo pipefail

env_file="${FAIRPLAY_AGENT_ENV:-$HOME/.config/fairplay-agents/app.env}"
# shellcheck source=/dev/null
[ -r "$env_file" ] && . "$env_file"
: "${FAIRPLAY_APP_ID:?set FAIRPLAY_APP_ID (in $env_file)}"
: "${FAIRPLAY_APP_KEY:?set FAIRPLAY_APP_KEY (in $env_file)}"
: "${FAIRPLAY_REPO:?set FAIRPLAY_REPO (in $env_file)}"
[ -r "$FAIRPLAY_APP_KEY" ] || { echo "gh-app-token: can't read $FAIRPLAY_APP_KEY" >&2; exit 1; }

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

# 1. A short-lived JWT signed with the App's key proves we are the App.
#    iat is backdated a minute to tolerate clock skew; GitHub caps exp at 10m.
now="$(date +%s)"
header="$(printf '{"alg":"RS256","typ":"JWT"}' | b64url)"
payload="$(printf '{"iat":%d,"exp":%d,"iss":"%s"}' "$((now - 60))" "$((now + 540))" "$FAIRPLAY_APP_ID" | b64url)"
sig="$(printf '%s.%s' "$header" "$payload" | openssl dgst -sha256 -sign "$FAIRPLAY_APP_KEY" -binary | b64url)"
jwt="$header.$payload.$sig"

api() {
  curl -fsS --retry 2 -X "$1" "https://api.github.com$2" \
    -H "Authorization: Bearer $jwt" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    ${3:+-d "$3"}
}

# 2. Find the App's installation on this repository...
installation="$(api GET "/repos/$FAIRPLAY_REPO/installation" | jq -r .id)"

# 3. ...and trade the JWT for an installation token limited to this one repo.
api POST "/app/installations/$installation/access_tokens" \
  "$(jq -cn --arg r "${FAIRPLAY_REPO#*/}" '{repositories: [$r]}')" | jq -r .token
