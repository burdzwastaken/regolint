package regolint.rules.errors.handling_test

import data.regolint.rules.errors.handling

test_allows_functions_without_error_return if {
	violations := handling.deny with input as {
		"functions": [{
			"name": "GetUser",
			"is_exported": true,
			"returns": [{"type": "User"}],
		}],
		"calls": [],
	}
	count(violations) == 0
}

test_allows_unexported_functions if {
	violations := handling.deny with input as {
		"functions": [{
			"name": "getUser",
			"is_exported": false,
			"returns": [{"type": "error"}],
		}],
		"calls": [{"function": "New", "package": "errors", "in_function": "getUser"}],
	}
	count(violations) == 0
}
