# ai-examples
Examples of AI Detection Use Cases

## Examples

- **[gitlost-data-leakage](gitlost-data-leakage/)** — Reproduces the
  [GitLost](https://noma.security/blog/gitlost-how-we-tricked-githubs-ai-agent-into-leaking-private-repos/)
  attack against a GitHub Agentic Workflow and stops it with LangGuard using
  **deterministic information-flow control**: an agent that reads a *private* repo and
  tries to post to a *public* one is blocked on the repository visibility labels — not
  on the contents of the data.
