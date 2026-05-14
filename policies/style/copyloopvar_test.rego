package regolint.rules.style.copyloopvar_test

import data.regolint.rules.style.copyloopvar

test_detects_loop_var_copy if {
	violations := copyloopvar.deny with input as {"loop_var_copies": [{
		"variable": "item",
		"kind": "value",
		"in_function": "process",
		"position": {"line": 4},
	}]}
	count(violations) == 1
	violations[_].rule == "copyloopvar"
}

test_allows_no_loop_var_copies if {
	violations := copyloopvar.deny with input as {"loop_var_copies": []}
	count(violations) == 0
}
