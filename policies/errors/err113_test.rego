package regolint.rules.errors.err113_test

import data.regolint.rules.errors.err113

test_detects_dynamic_errors_new_in_function if {
	violations := err113.deny with input as {"calls": [{
		"package": "errors",
		"function": "New",
		"in_function": "parse",
		"args": ["\"bad\""],
		"position": {"line": 5},
	}]}
	count(violations) == 1
	violations[_].rule == "err113"
}

test_allows_package_scope_sentinel_errors_new if {
	violations := err113.deny with input as {"calls": [{
		"package": "errors",
		"function": "New",
		"args": ["\"sentinel\""],
		"position": {"line": 3},
	}]}
	count(violations) == 0
}

test_detects_fmt_errorf_with_error_arg_without_wrap if {
	violations := err113.deny with input as {"calls": [{
		"package": "fmt",
		"function": "Errorf",
		"in_function": "load",
		"args": ["\"loading: %v\"", "err"],
		"position": {"line": 8},
	}]}
	count(violations) == 1
}

test_allows_fmt_errorf_with_error_wrap if {
	violations := err113.deny with input as {"calls": [{
		"package": "fmt",
		"function": "Errorf",
		"in_function": "load",
		"args": ["\"loading: %w\"", "err"],
		"position": {"line": 8},
	}]}
	count(violations) == 0
}

test_allows_fmt_errorf_without_error_arg if {
	violations := err113.deny with input as {"calls": [{
		"package": "fmt",
		"function": "Errorf",
		"in_function": "load",
		"args": ["\"blocked host %q\"", "host"],
		"position": {"line": 8},
	}]}
	count(violations) == 0
}
