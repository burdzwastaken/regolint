package regolint.rules.style.lll_test

import data.regolint.rules.style.lll

test_detects_long_line if {
	violations := lll.deny with input as {"lines": [{"number": 3, "length": 121, "position": {"line": 3}}]}
	count(violations) == 1
	violations[_].rule == "lll"
}

test_allows_line_at_limit if {
	violations := lll.deny with input as {"lines": [{"number": 3, "length": 120, "position": {"line": 3}}]}
	count(violations) == 0
}
