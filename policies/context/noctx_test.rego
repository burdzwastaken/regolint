package regolint.rules.context.noctx_test

import data.regolint.rules.context.noctx

test_detects_new_request_without_context if {
	violations := noctx.deny with input as {"calls": [{
		"package": "http",
		"function": "NewRequest",
		"in_function": "fetch",
		"position": {"line": 10},
	}]}
	count(violations) == 1
	violations[_].rule == "noctx"
}

test_allows_new_request_with_context if {
	violations := noctx.deny with input as {"calls": [{
		"package": "http",
		"function": "NewRequestWithContext",
		"in_function": "fetch",
		"position": {"line": 10},
	}]}
	count(violations) == 0
}

test_ignores_nested_function_literals if {
	violations := noctx.deny with input as {"calls": [{
		"package": "http",
		"function": "NewRequest",
		"in_function": "fetch",
		"in_func_lit": true,
		"position": {"line": 10},
	}]}
	count(violations) == 0
}
