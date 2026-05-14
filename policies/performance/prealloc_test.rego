package regolint.rules.performance.prealloc_test

import data.regolint.rules.performance.prealloc

test_detects_zero_length_make_before_loop_append if {
	violations := prealloc.deny with input as {
		"make_slices": [{
			"target": "out",
			"len_arg": "0",
			"has_cap": false,
			"in_function": "collect",
			"position": {"line": 5, "column": 9},
		}],
		"range_loops": [{
			"in_function": "collect",
			"position": {"line": 6, "column": 2},
			"end_line": 8,
		}],
		"appends": [{
			"target": "out",
			"source": "out",
			"in_function": "collect",
			"position": {"line": 7, "column": 9},
		}],
	}
	count(violations) == 1
	violations[_].rule == "prealloc"
}

test_allows_make_with_capacity if {
	violations := prealloc.deny with input as {
		"make_slices": [{
			"target": "out",
			"len_arg": "0",
			"cap_arg": "len(items)",
			"has_cap": true,
			"in_function": "collect",
			"position": {"line": 5, "column": 9},
		}],
		"range_loops": [{
			"in_function": "collect",
			"position": {"line": 6, "column": 2},
			"end_line": 8,
		}],
		"appends": [{
			"target": "out",
			"source": "out",
			"in_function": "collect",
			"position": {"line": 7, "column": 9},
		}],
	}
	count(violations) == 0
}

test_allows_append_outside_loop if {
	violations := prealloc.deny with input as {
		"make_slices": [{
			"target": "out",
			"len_arg": "0",
			"has_cap": false,
			"in_function": "collect",
			"position": {"line": 5, "column": 9},
		}],
		"range_loops": [{
			"in_function": "collect",
			"position": {"line": 6, "column": 2},
			"end_line": 8,
		}],
		"appends": [{
			"target": "out",
			"source": "out",
			"in_function": "collect",
			"position": {"line": 10, "column": 9},
		}],
	}
	count(violations) == 0
}

test_allows_different_append_source if {
	violations := prealloc.deny with input as {
		"make_slices": [{
			"target": "out",
			"len_arg": "0",
			"has_cap": false,
			"in_function": "collect",
			"position": {"line": 5, "column": 9},
		}],
		"range_loops": [{
			"in_function": "collect",
			"position": {"line": 6, "column": 2},
			"end_line": 8,
		}],
		"appends": [{
			"target": "out",
			"source": "other",
			"in_function": "collect",
			"position": {"line": 7, "column": 9},
		}],
	}
	count(violations) == 0
}
