package regolint.rules.context.usage_test

import data.regolint.rules.context.usage

test_allows_ctx_name if {
	violations := usage.deny with input as {"functions": [{
		"name": "GetUser",
		"is_exported": true,
		"parameters": [{"name": "ctx", "type": "context.Context"}],
	}]}
	count(violations) == 0
}

test_detects_wrong_context_name if {
	violations := usage.deny with input as {"functions": [{
		"name": "GetUser",
		"is_exported": true,
		"parameters": [{"name": "c", "type": "context.Context"}],
		"position": {"line": 10},
	}]}
	count(violations) == 1
}

test_detects_context_not_first if {
	violations := usage.deny with input as {"functions": [{
		"name": "GetUser",
		"is_exported": true,
		"parameters": [
			{"name": "id", "type": "string"},
			{"name": "ctx", "type": "context.Context"},
		],
		"position": {"line": 10},
	}]}
	count(violations) == 1
}

test_allows_no_context if {
	violations := usage.deny with input as {"functions": [{
		"name": "GetUser",
		"is_exported": true,
		"parameters": [{"name": "id", "type": "string"}],
	}]}
	count(violations) == 0
}

test_ignores_unexported if {
	violations := usage.deny with input as {"functions": [{
		"name": "getUser",
		"is_exported": false,
		"parameters": [{"name": "c", "type": "context.Context"}],
	}]}
	count(violations) == 0
}
