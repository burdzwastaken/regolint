package regolint.rules.style.nonamedreturns_test

import data.regolint.rules.style.nonamedreturns

test_detects_named_return if {
	violations := nonamedreturns.deny with input as {"functions": [{
		"name": "bad",
		"returns": [{"name": "err", "type": "error"}],
		"position": {"line": 3},
	}]}
	count(violations) == 1
	violations[_].rule == "nonamedreturns"
}

test_allows_unnamed_return if {
	violations := nonamedreturns.deny with input as {"functions": [{
		"name": "ok",
		"returns": [{"type": "error"}],
		"position": {"line": 3},
	}]}
	count(violations) == 0
}

test_allows_no_return_values if {
	violations := nonamedreturns.deny with input as {"functions": [{
		"name": "ok",
		"returns": [],
		"position": {"line": 3},
	}]}
	count(violations) == 0
}
