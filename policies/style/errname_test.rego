package regolint.rules.style.errname_test

import data.regolint.rules.style.errname

test_detects_bad_sentinel_error_name if {
	violations := errname.deny with input as {
		"variables": [{"name": "DatabaseError", "is_exported": true, "value": "errors.New(...)", "position": {"line": 3}}],
		"types": [],
		"functions": [],
	}
	count(violations) == 1
	violations[_].rule == "errname"
}

test_allows_err_prefix_sentinel if {
	violations := errname.deny with input as {
		"variables": [{"name": "ErrDatabase", "is_exported": true, "value": "errors.New(...)", "position": {"line": 3}}],
		"types": [],
		"functions": [],
	}
	count(violations) == 0
}

test_detects_bad_error_type_name if {
	violations := errname.deny with input as {
		"variables": [],
		"types": [{"name": "Failure", "is_exported": true, "position": {"line": 5}}],
		"functions": [{"name": "Error", "receiver": "*Failure", "position": {"line": 9}}],
	}
	count(violations) == 1
}

test_allows_error_type_suffix if {
	violations := errname.deny with input as {
		"variables": [],
		"types": [{"name": "FailureError", "is_exported": true, "position": {"line": 5}}],
		"functions": [{"name": "Error", "receiver": "FailureError", "position": {"line": 9}}],
	}
	count(violations) == 0
}
