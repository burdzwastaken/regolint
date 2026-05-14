package regolint.rules.style.nakedret_test

import data.regolint.rules.style.nakedret

test_detects_naked_return_with_named_result if {
	violations := nakedret.deny with input as {"functions": [{
		"name": "bad",
		"returns": [{"name": "err", "type": "error"}],
		"has_naked_ret": true,
		"position": {"line": 3},
	}]}
	count(violations) == 1
	violations[_].rule == "nakedret"
}

test_allows_explicit_return_with_named_result if {
	violations := nakedret.deny with input as {"functions": [{
		"name": "ok",
		"returns": [{"name": "err", "type": "error"}],
		"has_naked_ret": false,
		"position": {"line": 3},
	}]}
	count(violations) == 0
}

test_allows_naked_return_without_named_result if {
	violations := nakedret.deny with input as {"functions": [{
		"name": "ok",
		"returns": [{"type": "error"}],
		"has_naked_ret": true,
		"position": {"line": 3},
	}]}
	count(violations) == 0
}
