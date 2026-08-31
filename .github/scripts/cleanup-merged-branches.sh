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

candidates="$(mktemp)"
trap 'rm -f "$candidates"' EXIT

gh pr list \
  --repo "$REPOSITORY" \
  --state merged \
  --limit 10000 \
  --json headRefName,headRefOid,isCrossRepository \
  --jq '.[] | select(.isCrossRepository == false) | [.headRefName, .headRefOid] | @tsv' \
  > "$candidates"

deleted=0
eligible=0
skipped=0
declare -A processed=()

while IFS=$'\t' read -r branch merged_sha; do
  [[ -n "$branch" && -n "$merged_sha" ]] || continue
  [[ -z "${processed[$branch]:-}" ]] || continue

  encoded_branch="$(jq -rn --arg value "$branch" '$value | @uri')"
  branch_json="$(gh api "repos/$REPOSITORY/branches/$encoded_branch" 2>/dev/null || true)"
  [[ -n "$branch_json" ]] || continue

  current_sha="$(jq -r '.commit.sha' <<< "$branch_json")"
  matching_sha="$(awk -F '\t' -v name="$branch" -v sha="$current_sha" '$1 == name && $2 == sha { print $2; exit }' "$candidates")"
  if [[ -z "$matching_sha" ]]; then
    echo "SKIP  $branch (branch advanced after merge)"
    skipped=$((skipped + 1))
    processed[$branch]=1
    continue
  fi

  if [[ "$branch" == "$DEFAULT_BRANCH" ]]; then
    echo "SKIP  $branch (default branch)"
    skipped=$((skipped + 1))
    processed[$branch]=1
    continue
  fi

  protected="$(jq -r '.protected' <<< "$branch_json")"
  if [[ "$protected" == "true" ]]; then
    echo "SKIP  $branch (protected)"
    skipped=$((skipped + 1))
    processed[$branch]=1
    continue
  fi

  open_prs="$(gh pr list --repo "$REPOSITORY" --state open --head "$branch" --json number --jq 'length')"
  if [[ "$open_prs" != "0" ]]; then
    echo "SKIP  $branch (used by an open pull request)"
    skipped=$((skipped + 1))
    processed[$branch]=1
    continue
  fi

  eligible=$((eligible + 1))
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "WOULD DELETE  $branch"
  else
    gh api --method DELETE "repos/$REPOSITORY/git/refs/heads/$encoded_branch"
    echo "DELETED  $branch"
    deleted=$((deleted + 1))
  fi

  processed[$branch]=1
done < "$candidates"

echo "Eligible: $eligible; deleted: $deleted; skipped: $skipped; dry-run: $DRY_RUN"
