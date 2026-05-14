package regolint.rules.style.gochecknoglobals_test

import data.regolint.rules.style.gochecknoglobals

test_detects_package_variable if {
	violations := gochecknoglobals.deny with input as {"variables": [{"name": "global", "position": {"line": 3}}]}
	count(violations) == 1
	violations[_].rule == "gochecknoglobals"
}

test_allows_no_variables if {
	violations := gochecknoglobals.deny with input as {"variables": []}
	count(violations) == 0
}
