package regolint.rules.style.dogsled_test

import data.regolint.rules.style.dogsled

test_detects_too_many_blank_identifiers if {
	violations := dogsled.deny with input as {"blank_assignments": [{"blank_count": 3, "total_count": 4, "position": {"line": 5}}]}
	count(violations) == 1
	violations[_].rule == "dogsled"
}

test_allows_two_blank_identifiers if {
	violations := dogsled.deny with input as {"blank_assignments": [{"blank_count": 2, "total_count": 3, "position": {"line": 5}}]}
	count(violations) == 0
}
