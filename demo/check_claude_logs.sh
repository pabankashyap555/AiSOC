#!/usr/bin/env bash
# Where are Claude Code's logs getting stuck? Checks each hop and says which one fails.
#
#   cd /workspaces/AiSOC && ./demo/check_claude_logs.sh
#
# Hops: env file -> AiSOC OTLP receiver -> Kafka/fusion -> lake writer -> ClickHouse (Hunt reads this)
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

ENV_FILE="${CLAUDE_ENV_FILE:-/workspaces/ai-agent-gateway/demo/claude-code.env}"
ok()   { echo "  [OK]   $*"; }
bad()  { echo "  [FAIL] $*"; }
info() { echo "         $*"; }

ch() {  # ch "<sql>"
  local pw; pw="$(grep -E '^CLICKHOUSE_PASSWORD=' .env 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"')"
  docker exec aisoc-clickhouse clickhouse-client -u aisoc --password "${pw:-clickhouse_dev_secret}" -q "$1" 2>&1
}

echo "1. Claude Code settings file ($ENV_FILE)"
if [[ ! -f "$ENV_FILE" ]]; then
  bad "file missing: run ./demo/setup_claude_code.sh (without --gateway-only) in the gateway folder"
else
  endpoint="$(grep -oE 'OTEL_EXPORTER_OTLP_LOGS_ENDPOINT="[^"]+"' "$ENV_FILE" | cut -d'"' -f2)"
  token="$(grep -oE 'X-Inbox-Token=[^"]+' "$ENV_FILE" | cut -d= -f2)"
  if [[ -n "$endpoint" && -n "$token" ]]; then ok "telemetry settings present -> $endpoint"
  else bad "no telemetry settings: it was made with --gateway-only. Re-run ./demo/setup_claude_code.sh (no flag), then 'source demo/claude-code.env' again before starting claude"; fi
fi

echo "2. AiSOC OTLP receiver switched on"
if docker inspect aisoc-ingest --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | grep -qx 'AISOC_OTLP_LOGS_ENABLED=true'; then
  ok "AISOC_OTLP_LOGS_ENABLED=true on aisoc-ingest"
else
  bad "receiver is off (make up / make up-full turns it off again). Re-run ./demo/setup_claude_code.sh in the gateway folder"
fi

echo "3. Event lake running (needed for Hunt)"
if docker inspect aisoc-fusion --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | grep -qx 'AISOC_LAKE_WRITER_ENABLED=true'; then
  ok "lake writer on (fusion)"
else
  bad "lake writer is off: AiSOC was started with 'make up', not 'make up-full'"
fi
if docker ps --format '{{.Names}}' | grep -qx aisoc-clickhouse; then ok "ClickHouse running"; else bad "ClickHouse not running (needs make up-full)"; fi

echo "4. Test event end to end"
if [[ -n "${endpoint:-}" && -n "${token:-}" ]]; then
  marker="aisoc-otlp-check-$(date +%s)"
  now_ns="$(date +%s)000000000"
  body="{\"resourceLogs\":[{\"resource\":{\"attributes\":[{\"key\":\"service.name\",\"value\":{\"stringValue\":\"claude-code\"}}]},\"scopeLogs\":[{\"logRecords\":[{\"timeUnixNano\":\"$now_ns\",\"body\":{\"stringValue\":\"$marker\"},\"attributes\":[{\"key\":\"event.name\",\"value\":{\"stringValue\":\"check\"}}]}]}]}]}"
  code="$(curl -s -o /tmp/otlp_check.out -w '%{http_code}' -X POST "$endpoint" -H "X-Inbox-Token: $token" -H 'Content-Type: application/json' -d "$body")"
  if [[ "$code" == 200 ]]; then ok "receiver accepted a test record (HTTP 200)"; else bad "receiver answered HTTP $code: $(head -c 200 /tmp/otlp_check.out)"; fi
  if docker ps --format '{{.Names}}' | grep -qx aisoc-clickhouse; then
    found=0
    for _ in $(seq 1 15); do
      n="$(ch "SELECT count() FROM aisoc.raw_events WHERE positionCaseInsensitive(raw_payload, '$marker') > 0" | tail -1)"
      [[ "$n" =~ ^[1-9] ]] && { found=1; break; }
      sleep 3
    done
    if [[ "$found" == 1 ]]; then ok "test record reached the lake: Hunt can see OTLP events"
    else bad "test record did not reach the lake within 45 s (receiver -> Kafka -> fusion -> lake)"; info "fusion log: $(docker logs aisoc-fusion --since 2m 2>&1 | grep -iE 'lake|error' | tail -2 | cut -c1-160)"; fi
  fi
else
  info "skipped (no settings from step 1)"
fi

echo "5. Claude Code events already in the lake (last 3 hours)"
if docker ps --format '{{.Names}}' | grep -qx aisoc-clickhouse; then
  n="$(ch "SELECT count() FROM aisoc.raw_events WHERE event_time > now() - INTERVAL 3 HOUR AND positionCaseInsensitive(raw_payload, 'claude_code') > 0" | tail -1)"
  if [[ "$n" =~ ^[1-9] ]]; then ok "$n Claude Code event(s) stored: search Hunt for 'claude_code'"
  else bad "none stored yet: start Claude Code with 'source demo/claude-code.env && claude' (in the gateway folder) and use it for a minute"; fi
fi
