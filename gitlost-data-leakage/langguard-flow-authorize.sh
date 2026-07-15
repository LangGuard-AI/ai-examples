#!/usr/bin/env bash
#
# LangGuard flow-based arbiter — detect private→public information flow (GitLost).
#
# Instead of scanning the comment TEXT, this reconstructs the agent's tool-call
# trace, labels every repo it touched by GitHub visibility (a hard fact), and asks
# LangGuard to authorize the FLOW. A session that READ from a private repo and is
# WRITING to a public sink is a boundary crossing — blocked regardless of content
# (paraphrasing, encoding, or summarizing the private data cannot evade it).
#
set -euo pipefail

TD_DIR="/tmp/gh-aw/threat-detection"
VERDICT="$TD_DIR/detection_result.json"
mkdir -p "$TD_DIR"

write_safe()  { jq -n '{prompt_injection:false,secret_leak:false,malicious_patch:false,reasons:[]}' > "$VERDICT"; }
write_block() { jq -n --arg r "${1:-flow violation}" '{prompt_injection:false,secret_leak:true,malicious_patch:false,reasons:[$r]}' > "$VERDICT"; }
allow() { write_safe; echo "LangGuard flow arbiter: ALLOW — $1"; exit 0; }
deny()  { write_block "$1"; echo "::error title=Blocked by LangGuard (information-flow violation)::$1"; exit 1; }

# --- obtain the AUTHORITATIVE agent stream-json tool-call trace ---
# The detection job stages an EMPTY placeholder at /tmp/gh-aw/agent-stdio.log, so
# always download this run's 'agent' artifact and use that; only fall back to a
# staged copy if it actually contains tool calls.
TRACE=""
DLDIR="$TD_DIR/agent-artifact"
if [ -n "${GITHUB_RUN_ID:-}" ]; then
  rm -rf "$DLDIR"; mkdir -p "$DLDIR"
  gh run download "$GITHUB_RUN_ID" -R "${GITHUB_REPOSITORY:-}" -n agent -D "$DLDIR" >/dev/null 2>&1 || true
  [ -s "$DLDIR/agent-stdio.log" ] && TRACE="$DLDIR/agent-stdio.log"
fi
if [ -z "$TRACE" ]; then
  for c in "$TD_DIR/agent/agent-stdio.log" "$TD_DIR/agent-stdio.log" /tmp/gh-aw/agent-stdio.log; do
    if [ -s "$c" ] && grep -q '"type":"tool_use"' "$c" 2>/dev/null; then TRACE="$c"; break; fi
  done
fi
[ -n "$TRACE" ] || allow "no agent tool-call trace available (nothing to evaluate)"
echo "using tool-call trace: $TRACE ($(wc -l < "$TRACE") lines)"

jqtrace() { jq -R 'fromjson? // empty' "$TRACE" | jq -rc "$1"; }

# --- repos the agent READ from (github MCP calls carrying owner/repo) ---
mapfile -t READ_REPOS < <(jqtrace '
  select(.type=="assistant") | .message.content[]? | select(.type=="tool_use")
  | select(.name|startswith("mcp__github__"))
  | select(.input.owner and .input.repo) | "\(.input.owner)/\(.input.repo)"' | sort -u)

# --- did the agent propose a WRITE? read it from the STAGED SAFE-OUTPUTS, not the
# trace: the agent can emit a safe output via several paths (MCP tool, writing the
# safeoutputs file directly, a sub-agent), so agent_output.json is the reliable
# signal for "the agent is about to write to this repo". Sink = this workflow repo.
OUT="${GH_AW_AGENT_OUTPUT:-$TD_DIR/agent_output.json}"
WROTE=""
if [ -s "$OUT" ] && jq -e '(.items // []) | map(select(.type != "noop" and .type != "missing_tool" and .type != "report_incomplete")) | length > 0' "$OUT" >/dev/null 2>&1; then
  WROTE="$(jq -r '[.items[]? | .type] | join(",")' "$OUT" 2>/dev/null)"
fi

echo "reads: ${READ_REPOS[*]:-none}"
echo "write: ${WROTE:-none}  (sink repo: ${GITHUB_REPOSITORY:-unknown})"

# --- label each repo by GitHub visibility (ground truth, not content) ---
# The detection job's own GITHUB_TOKEN is scoped to THIS repo and cannot see the
# private source repo, so visibility is resolved with VIS_TOKEN (the same elevated
# token the agent read with). If VIS_TOKEN can't see a repo, that's "unknown".
vis() { local v; v=$(GH_TOKEN="${VIS_TOKEN:-${GH_TOKEN:-}}" gh api "repos/$1" --jq '.private' 2>/dev/null || echo ""); case "$v" in
  true) echo private;; false) echo public;; *) echo unknown;; esac; }

TC='[]'
for r in "${READ_REPOS[@]:-}"; do
  [ -z "$r" ] && continue
  v=$(vis "$r"); echo "  READ  $r -> $v"
  TC=$(jq -c --arg repo "$r" --arg v "$v" '. + [{action:"read",  repo:$repo, visibility:$v}]' <<<"$TC")
done
if [ -n "$WROTE" ] && [ -n "${GITHUB_REPOSITORY:-}" ]; then
  wv=$(vis "$GITHUB_REPOSITORY"); echo "  WRITE $GITHUB_REPOSITORY -> $wv"
  TC=$(jq -c --arg repo "$GITHUB_REPOSITORY" --arg v "$wv" '. + [{action:"write", repo:$repo, visibility:$v}]' <<<"$TC")
fi

MANIFEST=$(jq -cn --argjson tc "$TC" '{tool_calls:$tc}')
echo "flow manifest (labels only, no data): $MANIFEST"

# --- authorize the FLOW ---
if [ -n "${ARBITER_URL:-}" ]; then
  # LangGuard is the policy authority: send the labeled manifest as trace output.
  REQ=$(jq -cn --arg m "$MANIFEST" '{texts:[$m], input_type:"response"}')
  RAW=$(curl -sS --max-time 20 -w $'\n%{http_code}' \
          -H "Authorization: Bearer ${LANGGUARD_TOKEN:-}" -H "Content-Type: application/json" \
          -H "X-LiteLLM-Mode: post_call" -d "$REQ" "$ARBITER_URL") \
    || deny "LangGuard unreachable — failing closed"
  HTTP=$(tail -n1 <<<"$RAW"); BODY=$(sed '$d' <<<"$RAW")
  echo "LangGuard HTTP $HTTP: $BODY"
  [ "$HTTP" = "200" ] || deny "LangGuard returned HTTP $HTTP — failing closed"
  ACTION=$(jq -r '.action // "BLOCKED"' <<<"$BODY")
  case "$ACTION" in
    NONE|GUARDRAIL_INTERVENED) allow "LangGuard authorized the flow (action=$ACTION)";;
    *) deny "$(jq -r '.blocked_reason // "cross-boundary information flow"' <<<"$BODY")";;
  esac
else
  # Deterministic local fallback (no external PDP): the same flow invariant.
  if jq -e '([.tool_calls[]|select(.action=="read"  and .visibility=="private")]|length>0)
        and ([.tool_calls[]|select(.action=="write" and .visibility=="public") ]|length>0)' <<<"$MANIFEST" >/dev/null; then
    deny "session read a PRIVATE repo and writes to a PUBLIC sink (local flow rule)"
  fi
  allow "no private→public crossing (local flow rule)"
fi
