package regolint.rules.style.canonicalheader_test

import data.regolint.rules.style.canonicalheader

test_detects_noncanonical_header_literal if {
	violations := canonicalheader.deny with input as {"literals": [{"kind": "string", "value": "\"content-type\"", "position": {"line": 8}}]}
	count(violations) == 1
	violations[_].rule == "canonicalheader"
}

test_detects_noncanonical_top_level_constant if {
	violations := canonicalheader.deny with input as {"constants": [{"name": "header", "value": "\"user-agent\"", "position": {"line": 4}}]}
	count(violations) == 1
}

test_allows_canonical_header_literal if {
	violations := canonicalheader.deny with input as {"literals": [{"kind": "string", "value": "\"Content-Type\"", "position": {"line": 8}}]}
	count(violations) == 0
}

test_allows_unknown_string_literal if {
	violations := canonicalheader.deny with input as {"literals": [{"kind": "string", "value": "\"X-Custom-Header\"", "position": {"line": 8}}]}
	count(violations) == 0
}
