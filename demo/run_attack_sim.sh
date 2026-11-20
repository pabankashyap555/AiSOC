#!/usr/bin/env bash
# Run the "Operation Paper Trail" attack simulation against a running AiSOC.
#
#   ./demo/run_attack_sim.sh              # all 8 stages, fast
#   ./demo/run_attack_sim.sh --pause 20   # slower, for presenting live
#   ./demo/run_attack_sim.sh --findings   # safety net: every event becomes an alert
#
# Needs: AiSOC already up (`make up`) and an admin created (make up does that).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Same compose invocation the Makefile uses, so a port that `make up` moved
# (docker-compose.ports.yml) is honoured.
COMPOSE=(docker compose)
if [[ -f docker-compose.ports.yml ]]; then
  COMPOSE+=(-f docker-compose.yml -f docker-compose.ports.yml)
fi

host_port() {  # host_port <service> <container-port> <fallback>
  local p
  p="$("${COMPOSE[@]}" port "$1" "$2" 2>/dev/null | tail -n1 | sed -E 's/.*:([0-9]+)$/\1/')" || true
  echo "${p:-$3}"
}

if ! "${COMPOSE[@]}" ps --status running --services 2>/dev/null | grep -qx ingest-worker; then
  echo "AiSOC does not look like it is running. Start it with 'make up' (then 'make doctor' if unsure)." >&2
  exit 1
fi

AISOC_INGEST_URL="http://localhost:$(host_port ingest-worker 8080 8081)"
AISOC_API_URL="http://localhost:$(host_port api 8000 8000)"
export AISOC_INGEST_URL AISOC_API_URL

echo "Minting an ingest token and an API read token..."
AISOC_INGEST_TOKEN="$("${COMPOSE[@]}" run --rm -T api python -m app.scripts.mint_ingest_token --quiet)"
AISOC_API_TOKEN="$("${COMPOSE[@]}" run --rm -T api python -m app.scripts.mint_api_token --quiet)"
export AISOC_INGEST_TOKEN AISOC_API_TOKEN

exec python3 demo/attack_sim.py "$@"
