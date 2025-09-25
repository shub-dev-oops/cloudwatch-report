#!/usr/bin/env bash
set -euo pipefail

NS="hpa"
DEP="aasmp-swagitadminweb-hpa"

mem_to_mi() {
  # Convert values like "123Mi", "1.2Gi" to Mi (integer); fall back to 0 if empty/-
  v="${1:-0}"
  case "$v" in
    *Gi) awk -v n="${v%Gi}" 'BEGIN{printf "%d", n*1024}' ;;
    *Mi) awk -v n="${v%Mi}" 'BEGIN{printf "%d", n}' ;;
    *Ki) awk -v n="${v%Ki}" 'BEGIN{printf "%d", n/1024}' ;;
    *m)  echo 0 ;;       # not expected for memory but just in case
    ""|"-") echo 0 ;;
    *) echo "$v" | sed 's/[^0-9.]//g' ;;
  esac
}

# Build the label selector from the Deployment itself (robust & label-agnostic)
SEL=$(kubectl -n "$NS" get deploy "$DEP" -o json \
  | jq -r '.spec.selector.matchLabels | to_entries | map("\(.key)=\(.value)") | join(",")')

# Gather usage from metrics-server
declare -A USAGE   # key: pod/container -> Mi
while read -r pod c mem _; do
  [ -z "$pod" ] && continue
  USAGE["$pod/$c"]="$(mem_to_mi "$mem")"
done < <(kubectl -n "$NS" top pod -l "$SEL" --containers --no-headers 2>/dev/null || true)

# Print header
printf "%-48s %-14s %-14s %-14s %-12s\n" "POD/CONTAINER" "USAGE(Mi)" "REQUEST(Mi)" "LIMIT(Mi)" "STATUS"

# For each running pod, compare usage vs requests/limits
kubectl -n "$NS" get pod -l "$SEL" -o json | jq -r '
  .items[] | select(.status.phase=="Running") |
  . as $pod |
  .spec.containers[] |
  [$pod.metadata.name, .name,
   (.resources.requests.memory // ""),
   (.resources.limits.memory // "")]
  | @tsv' | while IFS=$'\t' read -r POD C REQ LMT; do
    U="${USAGE["$POD/$C"]:-0}"
    R="$(mem_to_mi "$REQ")"
    L="$(mem_to_mi "$LMT")"

    STATUS="ok"
    if [ "$R" -gt 0 ] && [ "$U" -gt "$R" ]; then STATUS="over-request"; fi
    if [ "$L" -gt 0 ] && [ "$U" -ge "$L" ]; then STATUS="AT-LIMIT"; fi
    if [ "$L" -gt 0 ]; then
      # warn if >= 90% of limit
      THRESH=$(( L * 90 / 100 ))
      if [ "$U" -ge "$THRESH" ] && [ "$U" -lt "$L" ]; then STATUS="near-limit"; fi
    fi

    printf "%-48s %-14s %-14s %-14s %-12s\n" \
      "$POD/$C" "$U" "$R" "$L" "$STATUS"
done

# Bonus: show any recent OOMKills (a smoking gun for hitting memory limits)
echo
echo "Recent OOMKilled containers:"
kubectl -n "$NS" get pod -l "$SEL" -o json \
 | jq -r '
    .items[] as $p
    | $p.status.containerStatuses[]? 
    | select(.lastState.terminated?.reason=="OOMKilled" or (.state.waiting?.message|tostring|test("OOMKilled")))
    | "\($p.metadata.name)/\(.name): OOMKilled"
  ' || true