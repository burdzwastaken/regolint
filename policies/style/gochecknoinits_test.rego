package regolint.rules.style.gochecknoinits_test

import data.regolint.rules.style.gochecknoinits

test_detects_init_function if {
	violations := gochecknoinits.deny with input as {"functions": [{"name": "init", "position": {"line": 3}}]}
	count(violations) == 1
	violations[_].rule == "gochecknoinits"
}

test_allows_regular_function if {
	violations := gochecknoinits.deny with input as {"functions": [{"name": "setup", "position": {"line": 3}}]}
	count(violations) == 0
}
