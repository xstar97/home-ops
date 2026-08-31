#!/usr/bin/env bash

set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN is required}"
: "${REPOSITORY:?REPOSITORY is required}"
: "${DEFAULT_BRANCH:?DEFAULT_BRANCH is required}"
: "${DRY_RUN:=true}"

if [[ "$DRY_RUN" != "true" && "$DRY_RUN" != "false" ]]; then
  echo "DRY_RUN must be true or false" >&2
  exit 2
fi

cleanup_workdir="$(mktemp -d)"
trap 'rm -rf "$cleanup_workdir"' EXIT

# Fetch each data set once. The previous implementation made API requests for
# every historical PR branch, which was unnecessarily slow on large repos.
gh api \
  --paginate \
  "repos/$REPOSITORY/branches?per_page=100" \
  --jq '.[] | [.name, .commit.sha, .protected] | @tsv' \
  > "$cleanup_workdir/branches"

gh pr list \
  --repo "$REPOSITORY" \
  --state merged \
  --limit 10000 \
  --json headRefName,headRefOid,isCrossRepository \
  --jq '.[] | select(.isCrossRepository == false) | [.headRefName, .headRefOid] | @tsv' \
  > "$cleanup_workdir/merged"

gh pr list \
  --repo "$REPOSITORY" \
  --state open \
  --limit 1000 \
  --json headRefName,isCrossRepository \
  --jq '.[] | select(.isCrossRepository == false) | .headRefName' \
  > "$cleanup_workdir/open"

deleted=0
eligible=0
skipped=0

# Iterate only over branches that still exist in the repository. A branch is
# eligible only when its current tip matches the head SHA of a merged PR.
while IFS=$'\t' read -r branch current_sha protected; do
  [[ -n "$branch" && -n "$current_sha" ]] || continue

  matching_sha="$(awk -F '\t' -v name="$branch" -v sha="$current_sha" '$1 == name && $2 == sha { print $2; exit }' "$cleanup_workdir/merged")"
  [[ -n "$matching_sha" ]] || continue

  if [[ "$branch" == "$DEFAULT_BRANCH" ]]; then
    echo "SKIP  $branch (default branch)"
    skipped=$((skipped + 1))
    continue
  fi

  if [[ "$protected" == "true" ]]; then
    echo "SKIP  $branch (protected)"
    skipped=$((skipped + 1))
    continue
  fi

  if grep -Fqx -- "$branch" "$cleanup_workdir/open"; then
    echo "SKIP  $branch (used by an open pull request)"
    skipped=$((skipped + 1))
    continue
  fi

  eligible=$((eligible + 1))
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "WOULD DELETE  $branch"
  else
    encoded_branch="$(jq -rn --arg value "$branch" '$value | @uri')"
    gh api --method DELETE "repos/$REPOSITORY/git/refs/heads/$encoded_branch"
    echo "DELETED  $branch"
    deleted=$((deleted + 1))
  fi
done < "$cleanup_workdir/branches"

echo "Eligible: $eligible; deleted: $deleted; skipped: $skipped; dry-run: $DRY_RUN"
