package regolint.rules.style.containedctx_test

import data.regolint.rules.style.containedctx

test_detects_context_field if {
	violations := containedctx.deny with input as {"types": [{
		"name": "Worker",
		"kind": "struct",
		"fields": [{"name": "ctx", "type": "context.Context", "position": {"line": 4}}],
	}]}
	count(violations) == 1
	violations[_].rule == "containedctx"
}

test_allows_non_context_field if {
	violations := containedctx.deny with input as {"types": [{
		"name": "Worker",
		"kind": "struct",
		"fields": [{"name": "logger", "type": "Logger", "position": {"line": 4}}],
	}]}
	count(violations) == 0
}
