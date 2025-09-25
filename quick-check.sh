#!/usr/bin/env bash
set -euo pipefail

NS="swagit"
HPA="aasmp-swagitadminweb-hpa"

# --- helpers ---------------------------------------------------------------
mem_to_mi() {
  v="${1:-0}"
  case "$v" in
    *Gi) awk -v n="${v%Gi}" 'BEGIN{printf "%d", n*1024}' ;;
    *Mi) awk -v n="${v%Mi}" 'BEGIN{printf "%d", n}' ;;
    *Ki) awk -v n="${v%Ki}" 'BEGIN{printf "%d", n/1024}' ;;
    ""|"-") echo 0 ;;
    *) echo "$v" | sed 's/[^0-9.]//g' ;;
  esac
}

# Build a label selector string from a scalable target (Deployment/SS/RS/DS).
# Falls back to pod-template labels if matchLabels is missing.
build_selector() {
  local kind="$1" name="$2"
  kubectl -n "$NS" get "$kind" "$name" -o json \
  | jq -r '
      .spec.selector.matchLabels // .spec.selector // .spec.template.metadata.labels // {} 
      | to_entries | map("\(.key)=\(.value)") | join(",")
    '
}

# --- 1) Discover target from HPA ------------------------------------------
read -r TARGET_KIND TARGET_NAME <<<"$(
  kubectl -n "$NS" get hpa "$HPA" -o json \
  | jq -r '.spec.scaleTargetRef.kind + " " + .spec.scaleTargetRef.name'
)"

if [[ -z "$TARGET_KIND" || -z "$TARGET_NAME" || "$TARGET_KIND" == "null" ]]; then
  echo "Could not read scaleTargetRef from HPA $HPA in ns $NS"; exit 1
fi

SEL="$(build_selector "$TARGET_KIND" "$TARGET_NAME")"
if [[ -z "$SEL" ]]; then
  echo "Could not derive a label selector from $TARGET_KIND/$TARGET_NAME; trying ownerRef fallback..."
  # Fallback: grab pods owned (directly/indirectly) by the target name
  PODS_JSON="$(kubectl -n "$NS" get pods -o json)"
else
  PODS_JSON="$(kubectl -n "$NS" get pods -l "$SEL" -o json)"
fi

# If selector path was empty, filter by owner/name as a best effort.
if [[ -z "$SEL" ]]; then
  PODS_JSON="$(echo "$PODS_JSON" | jq --arg n "$TARGET_NAME" '
    .items |= ( .items | map(
      select(
        (.metadata.ownerReferences[]?.name == $n) or
        (.metadata.generateName | startswith($n+"-")) or
        (.metadata.name | startswith($n+"-"))
      )
    ))
  ')"
fi

# --- 2) Pull live usage from metrics-server --------------------------------
declare -A USAGE # key: pod/container -> Mi
# Try to reuse selector when possible; otherwise list all pods and filter below
if [[ -n "$SEL" ]]; then
  TOP=$(kubectl -n "$NS" top pod -l "$SEL" --containers --no-headers 2>/dev/null || true)
else
  TOP=$(kubectl -n "$NS" top pod --containers --no-headers 2>/dev/null || true)
fi
while read -r pod c mem _; do
  [[ -z "${pod:-}" ]] && continue
  USAGE["$pod/$c"]="$(mem_to_mi "$mem")"
done <<<"$TOP"

# --- 3) Emit comparison table ----------------------------------------------
printf "Target: %s/%s in ns=%s  | Selector: %s\n\n" "$TARGET_KIND" "$TARGET_NAME" "$NS" "${SEL:-<ownerRef-fallback>}"
printf "%-52s %-12s %-12s %-12s %-12s\n" "POD/CONTAINER" "USAGE(Mi)" "REQUEST(Mi)" "LIMIT(Mi)" "STATUS"

echo "$PODS_JSON" | jq -r '
  .items[] | select(.status.phase=="Running") as $p
  | $p.spec.containers[]
  | [$p.metadata.name, .name, (.resources.requests.memory // ""), (.resources.limits.memory // "")]
  | @tsv
' | while IFS=$'\t' read -r POD C REQ LMT; do
  U="${USAGE["$POD/$C"]:-0}"
  R="$(mem_to_mi "$REQ")"
  L="$(mem_to_mi "$LMT")"

  STATUS="ok"
  if (( R > 0 && U > R )); then STATUS="over-request"; fi
  if (( L > 0 && U >= L )); then STATUS="AT-LIMIT"; fi
  if (( L > 0 )); then
    THRESH=$(( L * 90 / 100 ))
    if (( U >= THRESH && U < L )); then STATUS="near-limit"; fi
  fi

  printf "%-52s %-12s %-12s %-12s %-12s\n" "$POD/$C" "$U" "$R" "$L" "$STATUS"
done

# --- 4) Show recent OOMKills -----------------------------------------------
echo
echo "Recent OOMKilled containers:"
echo "$PODS_JSON" \
| jq -r '
    .items[] as $p
    | $p.status.containerStatuses[]? 
    | select(.lastState.terminated?.reason=="OOMKilled" or (.state.waiting?.message|tostring|test("OOMKilled")))
    | "\($p.metadata.name)/\(.name): OOMKilled"
  ' || true

# --- 5) HPA memory-metric sanity check -------------------------------------
echo
echo "HPA resource metrics (look for memory utilization targets):"
kubectl -n "$NS" get hpa "$HPA" -o json | jq '.spec.metrics // []'