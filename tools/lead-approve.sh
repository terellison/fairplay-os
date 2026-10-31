#!/usr/bin/env bash
# Approve a worker's pull request as the lead agent (the fairplay-os-lead
# GitHub App). This is the only way the lead approves anything, so it is the
# one command the owner allows the lead to run without asking.
#
#   tools/lead-approve.sh <pr-number> <reviewed-head-sha> <review-file>
#
# It refuses unless the PR is open against master, was opened by a worker
# (fairplay-os-agents), isn't labelled lead-authored (the lead never approves
# its own work), and its head is still the commit the lead reviewed. The
# review file's text is posted with the approval, so every approval says why.
# It never merges: auto-merge does that once checks pass, and CODEOWNERS
# still requires the owner for design and workflow files.
#
# Config: ~/.config/fairplay-lead/app.env (overridable with FAIRPLAY_LEAD_ENV),
# in the format tools/gh-app-token.sh reads.
set -euo pipefail

die() { echo "lead-approve: $*" >&2; exit 1; }

[ $# -eq 3 ] || die "usage: $0 <pr-number> <reviewed-head-sha> <review-file>"
pr="$1" sha="$2" review="$3"
[[ "$pr" =~ ^[0-9]+$ ]] || die "PR number must be digits: $pr"
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || die "give the full 40-character head SHA you reviewed: $sha"
[ -s "$review" ] || die "review file is missing or empty: $review"

env_file="${FAIRPLAY_LEAD_ENV:-$HOME/.config/fairplay-lead/app.env}"
# shellcheck source=/dev/null
. "$env_file"
: "${FAIRPLAY_REPO:?set FAIRPLAY_REPO (in $env_file)}"

GH_TOKEN="$(FAIRPLAY_AGENT_ENV="$env_file" "$(dirname "$0")/gh-app-token.sh")"
export GH_TOKEN

info="$(gh api "repos/$FAIRPLAY_REPO/pulls/$pr" --jq \
  '[.state, .base.ref, .head.sha, .user.login, ([.labels[].name] | join(","))] | @tsv')"
IFS=$'\t' read -r state base head author labels <<<"$info"

[ "$state" = open ] || die "PR #$pr is $state"
[ "$base" = master ] || die "PR #$pr targets $base, not master"
[ "$author" = 'fairplay-os-agents[bot]' ] || die "PR #$pr was opened by $author, not a worker"
case ",$labels," in *,lead-authored,*) die "PR #$pr is labelled lead-authored; the owner reviews it" ;; esac
[ "$head" = "$sha" ] || die "PR #$pr moved to $head since you reviewed $sha; review again"

gh api -X POST "repos/$FAIRPLAY_REPO/pulls/$pr/reviews" \
  -f event=APPROVE -f commit_id="$sha" -F body=@"$review" \
  --jq '"approved #'"$pr"' at " + .commit_id[0:12] + " as " + .user.login'
