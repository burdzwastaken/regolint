package regolint.rules.package.complexity_test

import data.regolint.rules.package.complexity

test_detects_high_complexity if {
	violations := complexity.deny with input as {"all_functions": [{
		"name": "complexFunc",
		"complexity": 20,
		"line_count": 30,
		"position": {"line": 10},
	}]}
	count(violations) == 1
}

test_allows_normal_complexity if {
	violations := complexity.deny with input as {"all_functions": [{
		"name": "simpleFunc",
		"complexity": 5,
		"line_count": 20,
		"position": {"line": 10},
	}]}
	count(violations) == 0
}

test_detects_long_function if {
	violations := complexity.deny with input as {"all_functions": [{
		"name": "longFunc",
		"complexity": 5,
		"line_count": 100,
		"position": {"line": 10},
	}]}
	count(violations) == 1
}

test_detects_both_issues if {
	violations := complexity.deny with input as {"all_functions": [{
		"name": "badFunc",
		"complexity": 20,
		"line_count": 100,
		"position": {"line": 10},
	}]}
	count(violations) == 2
}
