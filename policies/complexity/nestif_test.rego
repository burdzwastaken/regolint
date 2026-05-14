package regolint.rules.complexity.nestif_test

import data.regolint.rules.complexity.nestif

test_detects_deeply_nested_if if {
	violations := nestif.deny with input as {"functions": [{"name": "tooDeep", "max_if_depth": 6, "position": {"line": 3}}]}
	count(violations) == 1
	violations[_].rule == "nestif"
}

test_allows_if_depth_at_limit if {
	violations := nestif.deny with input as {"functions": [{"name": "ok", "max_if_depth": 5, "position": {"line": 3}}]}
	count(violations) == 0
}
