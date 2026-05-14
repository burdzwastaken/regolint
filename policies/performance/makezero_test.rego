package regolint.rules.performance.makezero_test

import data.regolint.rules.performance.makezero

test_detects_make_with_nonzero_length_then_append if {
	violations := makezero.deny with input as {
		"make_slices": [{"target": "items", "len_arg": "n", "in_function": "build", "position": {"line": 5, "column": 10}}],
		"appends": [{"target": "items", "source": "items", "in_function": "build", "position": {"line": 6, "column": 9}}],
	}
	count(violations) == 1
	violations[_].rule == "makezero"
}

test_allows_zero_length_make_before_append if {
	violations := makezero.deny with input as {
		"make_slices": [{"target": "items", "len_arg": "0", "cap_arg": "n", "has_cap": true, "in_function": "build", "position": {"line": 5, "column": 10}}],
		"appends": [{"target": "items", "source": "items", "in_function": "build", "position": {"line": 6, "column": 9}}],
	}
	count(violations) == 0
}

test_allows_append_before_make if {
	violations := makezero.deny with input as {
		"make_slices": [{"target": "items", "len_arg": "n", "in_function": "build", "position": {"line": 8, "column": 10}}],
		"appends": [{"target": "items", "source": "items", "in_function": "build", "position": {"line": 6, "column": 9}}],
	}
	count(violations) == 0
}

test_allows_different_append_source if {
	violations := makezero.deny with input as {
		"make_slices": [{"target": "items", "len_arg": "n", "in_function": "build", "position": {"line": 5, "column": 10}}],
		"appends": [{"target": "items", "source": "other", "in_function": "build", "position": {"line": 6, "column": 9}}],
	}
	count(violations) == 0
}

test_allows_different_function if {
	violations := makezero.deny with input as {
		"make_slices": [{"target": "items", "len_arg": "n", "in_function": "build", "position": {"line": 5, "column": 10}}],
		"appends": [{"target": "items", "source": "items", "in_function": "other", "position": {"line": 6, "column": 9}}],
	}
	count(violations) == 0
}
