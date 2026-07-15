# GitLost — stopping private→public data leakage with LangGuard

This example reproduces the [noma.security **GitLost**](https://noma.security/blog/gitlost-how-we-tricked-githubs-ai-agent-into-leaking-private-repos/)
class of attack against a [GitHub Agentic Workflow](https://github.github.com/gh-aw/),
and stops it with LangGuard using **deterministic information-flow control** — decided
on repository *visibility labels*, never on the contents of the data.

Proven live: an agent read a **private** repo and tried to post its config to a
**public** issue; LangGuard returned `BLOCKED` and the comment was never posted.

---

## 1. The attack

```
someone files a PUBLIC issue that points the agent at an internal repo
   agent (naïve, and over-permissioned: it can read a PRIVATE repo)
      ──▶ reads the PRIVATE repo for "context"
         ──▶ posts what it found as a PUBLIC comment      ← data exfiltration
```

Two ingredients make it work:
1. **The agent trusts issue content** — a helpful agent does what the issue asks.
2. **A private→public information path exists** — the agent can *read* a private repo
   and *write* to a public one in the same run.

GitLost delivered ingredient #1 via prompt injection. This example makes the agent
**deliberately naïve and over-permissioned** so the read reliably happens — because the
point is not "can we jailbreak the model," it's "**when data does cross the boundary,
does the control catch it?**"

## 2. Why not just scan the comment for secrets?

Content signatures are brittle. The agent can paraphrase, summarize, translate, base64,
split, or (as happened here) have the platform's own sanitizer redact a URL — and a
text filter misses it. The invariant that actually holds is the **flow**:

> A session that **read** from a `private` repo must not **write** to a `public` sink.

That is decided from provenance labels, so it holds regardless of what the data looks
like or whether anyone marked it sensitive.

## 3. How LangGuard detects it (deterministically)

The gate is [`langguard-flow-authorize.sh`](langguard-flow-authorize.sh), run in the
workflow's `threat-detection` job — *after* the agent proposes its comment, *before*
anything is posted. Because every safe-output job implicitly `needs:` this job, a
non-zero exit blocks **all** writes.

Step by step, the arbiter (a Policy Enforcement Point) builds a provenance manifest:

1. **Get the authoritative tool-call trace.** It downloads this run's `agent` artifact
   (`agent-stdio.log`, the Claude Code stream-json) — *not* the empty placeholder the
   detection job stages.
2. **Extract every repo the agent READ** — `mcp__github__*` calls carrying `owner`/`repo`
   (`get_file_contents`, `issue_read`, …).
3. **Extract the WRITE** from gh-aw's staged safe-outputs (`agent_output.json`). If the
   agent proposed any real output (an `add_comment`, etc.), the sink is **this repo**.
   (Reading the write from the proposed safe-output — not from a specific tool call —
   is what makes detection robust to *how* the agent emitted it.)
4. **Label every repo by GitHub visibility** — the ground truth, `GET /repos/{o}/{r}.private`.
5. **Emit a manifest of labels only — never the data:**
   ```json
   {"tool_calls":[
     {"action":"read","repo":"LangGuard-AI/ai-examples","visibility":"public"},
     {"action":"read","repo":"LangGuard-AI/demo_private","visibility":"private"},
     {"action":"write","repo":"LangGuard-AI/ai-examples","visibility":"public"}]}
   ```
6. **Ask LangGuard.** The manifest is sent to the LangGuard guardrail endpoint; the
   [flow policy](policy/flow-boundary.rego) evaluates it and returns `BLOCKED` on a
   private→public crossing. Non-zero exit → gh-aw blocks the comment.

The agent read the private data *inside the sandbox*, but **nothing egresses** — the
comment is never posted.

```
issue ──▶ agent (reads ai-examples[public] + demo_private[PRIVATE], proposes a comment)
            │
            ▼  threat-detection job
      flow arbiter ──build labeled manifest──▶ LangGuard flow policy
            │                                      │
            │   read:private + write:public  ──▶  BLOCKED
            ▼
      detection FAILS ──▶ safe-outputs SKIPPED ──▶ no comment, no leak
```

## 4. The LangGuard policy

[`policy/flow-boundary.rego`](policy/flow-boundary.rego) decides purely on the labels —
`read:private ∧ write:public ⇒ critical violation ⇒ BLOCKED`. It never reads the data.
Create it in LangGuard (**Policies → new OPA policy**) and activate it.

## 5. What's in this example

| File | Purpose |
|------|---------|
| [`../.github/workflows/gitlost-data-leakage.md`](../.github/workflows/gitlost-data-leakage.md) | The gh-aw workflow (naïve triage agent on Amazon Bedrock; `threat-detection` gate). |
| [`langguard-flow-authorize.sh`](langguard-flow-authorize.sh) | The flow arbiter (PEP): builds the labeled manifest and calls LangGuard. |
| [`policy/flow-boundary.rego`](policy/flow-boundary.rego) | The LangGuard information-flow policy (paste into the UI). |
| [`sample-issues/attack.md`](sample-issues/attack.md) | Issue that points the agent at the private repo → **BLOCKED**. |
| [`sample-issues/benign.md`](sample-issues/benign.md) | Ordinary issue → agent reads only public → **ALLOWED**, comment posts. |

## 6. Running it

**The vulnerable configuration (what the demo is about):**
- The github-MCP server uses a PAT (`GH_AW_GITHUB_MCP_SERVER_TOKEN`) that can read a
  **private** repo, and the workflow enables the `repos` toolset — so `get_file_contents`
  on the private repo is possible. This over-broad access is the exposure; LangGuard is
  the compensating control.

**Prereqs (repo secrets / variables):**
- `GH_AW_GITHUB_MCP_SERVER_TOKEN` — PAT with **contents:read** on this repo *and* the
  private source repo.
- `LANGGUARD_ARBITER_URL` (var) + `LANGGUARD_TOKEN` (secret) — LangGuard guardrail endpoint + API key.
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` and a dummy `ANTHROPIC_API_KEY` — Claude Code on Bedrock.
- Activate `policy/flow-boundary.rego` in LangGuard.

**Then:**
- **Attack:** open an issue like [`sample-issues/attack.md`](sample-issues/attack.md)
  (points the agent at the private repo). → agent reads it → arbiter manifest shows
  `read:private + write:public` → **LangGuard `BLOCKED`** → no comment.
- **Benign:** open [`sample-issues/benign.md`](sample-issues/benign.md) → agent reads
  only this public repo → **`NONE`** → comment posts.

Watch under the repo's **Actions** tab, or inspect the `detection` job's arbiter step.

## 7. Notes & limitations

- **Stronger placement:** enforcing at `pre_mcp_call` (block the private *read* when the
  session was triggered by a public issue) stops it even earlier. This example gates the
  proposed *write*, which already prevents the leak.
- The write sink here is the workflow's own repo (a public issue comment). The same
  manifest generalizes to other sinks (PRs, dispatches, external calls) by labeling them.
- Visibility is resolved with the same elevated token the agent read with, so the
  arbiter sees exactly what the agent could.
