package regolint.rules.context.fatcontext_test

import data.regolint.rules.context.fatcontext

test_detects_context_derivation_inside_range_loop if {
	violations := fatcontext.deny with input as {
		"range_loops": [{
			"in_function": "process",
			"position": {"line": 10},
			"end_line": 20,
		}],
		"calls": [{
			"package": "context",
			"function": "WithValue",
			"in_function": "process",
			"position": {"line": 14},
		}],
	}
	count(violations) == 1
	violations[_].rule == "fatcontext"
}

test_allows_context_derivation_outside_range_loop if {
	violations := fatcontext.deny with input as {
		"range_loops": [{
			"in_function": "process",
			"position": {"line": 10},
			"end_line": 20,
		}],
		"calls": [{
			"package": "context",
			"function": "WithTimeout",
			"in_function": "process",
			"position": {"line": 22},
		}],
	}
	count(violations) == 0
}

test_allows_non_context_call_inside_range_loop if {
	violations := fatcontext.deny with input as {
		"range_loops": [{
			"in_function": "process",
			"position": {"line": 10},
			"end_line": 20,
		}],
		"calls": [{
			"package": "fmt",
			"function": "Println",
			"in_function": "process",
			"position": {"line": 14},
		}],
	}
	count(violations) == 0
}

test_ignores_nested_function_literals if {
	violations := fatcontext.deny with input as {
		"range_loops": [{
			"in_function": "process",
			"position": {"line": 10},
			"end_line": 20,
		}],
		"calls": [{
			"package": "context",
			"function": "WithCancel",
			"in_function": "process",
			"in_func_lit": true,
			"position": {"line": 14},
		}],
	}
	count(violations) == 0
}
