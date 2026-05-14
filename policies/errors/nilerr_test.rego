package regolint.rules.errors.nilerr_test

import data.regolint.rules.errors.nilerr

test_detects_nil_error_after_err_check if {
	violations := nilerr.deny with input as {
		"functions": [{"name": "Find", "returns": [{"type": "*User"}, {"type": "error"}]}],
		"ifs": [{
			"function": "Find",
			"condition": "err != nil",
			"error_var": "err",
			"is_err_not_nil": true,
			"returns": [{"function": "Find", "results": ["nil", "nil"], "is_naked": false, "position": {"line": 6}}],
		}],
	}

	count(violations) == 1
	violations[_].rule == "nilerr"
}

test_allows_returning_checked_error if {
	violations := nilerr.deny with input as {
		"functions": [{"name": "Find", "returns": [{"type": "*User"}, {"type": "error"}]}],
		"ifs": [{
			"function": "Find",
			"error_var": "err",
			"is_err_not_nil": true,
			"returns": [{"function": "Find", "results": ["nil", "err"], "is_naked": false, "position": {"line": 6}}],
		}],
	}

	count(violations) == 0
}

test_allows_non_error_return_position if {
	violations := nilerr.deny with input as {
		"functions": [{"name": "Find", "returns": [{"type": "*User"}, {"type": "error"}]}],
		"ifs": [{
			"function": "Find",
			"error_var": "err",
			"is_err_not_nil": true,
			"returns": [{"function": "Find", "results": ["nil", "err"], "is_naked": false, "position": {"line": 6}}],
		}],
	}

	count(violations) == 0
}

test_allows_if_without_err_not_nil_condition if {
	violations := nilerr.deny with input as {
		"functions": [{"name": "Find", "returns": [{"type": "error"}]}],
		"ifs": [{
			"function": "Find",
			"is_err_not_nil": false,
			"returns": [{"function": "Find", "results": ["nil"], "is_naked": false, "position": {"line": 6}}],
		}],
	}

	count(violations) == 0
}

test_disambiguates_same_named_methods_by_receiver if {
	violations := nilerr.deny with input as {
		"functions": [
			{"name": "Read", "receiver": "*A", "returns": [{"type": "error"}]},
			{"name": "Read", "receiver": "B", "returns": [{"type": "int"}, {"type": "error"}]},
		],
		"ifs": [{
			"function": "Read",
			"receiver": "B",
			"error_var": "err",
			"is_err_not_nil": true,
			"returns": [{"function": "Read", "receiver": "B", "results": ["0", "nil"], "is_naked": false, "position": {"line": 10}}],
		}],
	}

	count(violations) == 1
	violations[_].position.line == 10
}
