package langguard.flow.boundary

# Information-flow / boundary-crossing policy for the GitLost example.
#
# The LangGuard flow arbiter (langguard-flow-authorize.sh) sends a provenance
# MANIFEST as the trace output — labels only, never the underlying data:
#
#   {"tool_calls":[{"action":"read","repo":"org/private","visibility":"private"},
#                  {"action":"write","repo":"org/public","visibility":"public"}]}
#
# The decision is made ENTIRELY on the visibility labels: a session that read from
# a private repo and writes to a public sink is a boundary crossing -> BLOCKED.
# Content is never inspected, so paraphrasing / encoding the private data cannot evade it.

import rego.v1

# Parse the manifest; default to empty so unrelated traffic never errors or matches.
default manifest := {"tool_calls": []}

manifest := json.unmarshal(input.trace.output) if {
	is_string(input.trace.output)
	startswith(input.trace.output, "{\"tool_calls\"")
}

reads_private if {
	some tc in manifest.tool_calls
	tc.action == "read"
	tc.visibility == "private"
}

writes_public if {
	some tc in manifest.tool_calls
	tc.action == "write"
	tc.visibility == "public"
}

# critical severity -> the guardrail returns BLOCKED
violation contains result if {
	reads_private
	writes_public
	result := {
		"type": "cross_boundary_exfiltration",
		"message": "Information-flow violation: session read a PRIVATE repository and is writing to a PUBLIC sink",
		"severity": "critical",
	}
}
