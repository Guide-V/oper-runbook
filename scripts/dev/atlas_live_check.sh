#!/usr/bin/env bash
# End-to-end check of `mongoops regex-finder atlas` against a real Atlas cluster.
#
#   1. create a temporary DB user scoped to the cluster (readWrite on mongoops_test only)
#   2. run scripts/dev/seed_regex_workload_atlas.js through mongosh
#   3. poll Performance Advisor via mongoops until the seeded regexes show up (ingestion lag)
#   4. run tests/integration/test_atlas_live.py
#   5. always: drop the seeded collection and delete the temporary user
#
# Requirements: Atlas CLI logged in (`atlas auth login`) with Project Owner on the project,
# mongosh, and a .env with MONGODB_ATLAS_PROJECT_ID plus an API key holding
# GROUP_DATA_ACCESS_READ_ONLY (see README "Credentials and environment").
#
# Usage: scripts/dev/atlas_live_check.sh [cluster-name]   (default: $ATLAS_CLUSTER or cluster-free)
set -euo pipefail

cd "$(dirname "$0")/../.."

# Only the project id is taken from .env. Deliberately NOT exporting the whole file: the Atlas
# CLI would pick up MONGODB_ATLAS_*_API_KEY and use the read-only key instead of the logged-in
# profile, so `dbusers create` would fail. mongoops loads .env by itself.
env_project_id() { [[ -f .env ]] && sed -n 's/^MONGODB_ATLAS_PROJECT_ID=//p' .env | tr -d '"' || true; }

CLUSTER="${1:-${ATLAS_CLUSTER:-cluster-free}}"
PROJECT_ID="${MONGODB_ATLAS_PROJECT_ID:-$(env_project_id)}"
[[ -n "$PROJECT_ID" ]] || { echo "MONGODB_ATLAS_PROJECT_ID missing (put it in .env)" >&2; exit 2; }
BIN="${BIN:-.venv/bin}"
SEED_DB="mongoops_test"
SEED_USER="mongoops_seed_$(date +%s)"
SEED_PW="$(openssl rand -hex 16)"
WAIT_SECONDS="${WAIT_SECONDS:-600}"
POLL_SECONDS=30

log() { printf '\033[1;32m[atlas-live]\033[0m %s\n' "$*" >&2; }
atlas_q() {  # run the Atlas CLI, hide its update nag, keep its exit status
  local out rc=0
  out="$(atlas "$@" 2>&1)" || rc=$?
  printf '%s\n' "$out" | grep -v -i 'atlascli' >&2 || true
  return $rc
}

cleanup() {
  set +e
  if [[ -n "${SRV:-}" ]]; then
    log "dropping ${SEED_DB}.customers"
    mongosh "${SRV}/${SEED_DB}" -u "$SEED_USER" -p "$SEED_PW" --quiet \
      --eval 'db.customers.drop()' >/dev/null 2>&1
  fi
  if [[ -n "${USER_CREATED:-}" ]]; then
    log "deleting temporary user ${SEED_USER}"
    atlas_q dbusers delete "$SEED_USER" --projectId "$PROJECT_ID" --force
  fi
}
trap cleanup EXIT

log "cluster=${CLUSTER} project=${PROJECT_ID}"
SRV="$(atlas clusters connectionStrings describe "$CLUSTER" --projectId "$PROJECT_ID" -o json \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["standardSrv"])')"

log "creating temporary user ${SEED_USER} (readWrite@${SEED_DB}, scope ${CLUSTER})"
atlas_q dbusers create --projectId "$PROJECT_ID" --username "$SEED_USER" --password "$SEED_PW" \
  --role "readWrite@${SEED_DB}" --scope "${CLUSTER}:CLUSTER"
USER_CREATED=1

ready=""
for i in $(seq 1 12); do
  if mongosh "${SRV}/${SEED_DB}" -u "$SEED_USER" -p "$SEED_PW" --quiet \
       --eval 'db.runCommand({ping:1}).ok' 2>/dev/null | grep -q 1; then
    ready=1; break
  fi
  log "waiting for user propagation ($i)"; sleep 10
done
[[ -n "$ready" ]] || { log "temporary user never became usable"; exit 1; }

log "seeding regex workload (MONGOOPS_SEED_DOCS=${MONGOOPS_SEED_DOCS:-300000})"
SEED_START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
seed_out="$(mongosh "${SRV}/${SEED_DB}?retryWrites=true&w=majority" -u "$SEED_USER" -p "$SEED_PW" \
  --quiet --file scripts/dev/seed_regex_workload_atlas.js)"
printf '%s\n' "$seed_out" | grep -v '^inserted' >&2 || true

log "waiting for Performance Advisor ingestion (up to ${WAIT_SECONDS}s)"
deadline=$(( $(date +%s) + WAIT_SECONDS ))
while :; do
  count="$("$BIN/mongoops" regex-finder atlas -c "$CLUSTER" --since "$SEED_START" \
             -n "${SEED_DB}.customers" -f json --view summary 2>/dev/null \
           | python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("summary", [])))' \
           || echo 0)"
  if [[ "$count" -ge 4 ]]; then
    log "Performance Advisor reports ${count} regex shape(s)"; break
  fi
  if (( $(date +%s) >= deadline )); then
    log "timed out: only ${count} shape(s) reported"; exit 1
  fi
  log "  ${count} shape(s) so far, retrying in ${POLL_SECONDS}s"; sleep "$POLL_SECONDS"
done

log "running integration test"
MONGOOPS_TEST_ATLAS_CLUSTER="$CLUSTER" MONGOOPS_TEST_ATLAS_SINCE="$SEED_START" \
  "$BIN/pytest" -q -m atlas_live tests/integration/test_atlas_live.py

log "report"
"$BIN/mongoops" regex-finder atlas -c "$CLUSTER" --since "$SEED_START" \
  -n "${SEED_DB}.customers" --view summary \
  --html "${HTML_REPORT:-reports/test-atlas-live-$(date -u +%Y%m%dT%H%M%SZ).html}"
