package regolint.rules.style.gocheckcompilerdirectives_test

import data.regolint.rules.style.gocheckcompilerdirectives

test_detects_unknown_go_directive if {
	violations := gocheckcompilerdirectives.deny with input as {"comments": [{"text": "go:wat", "raw": "//go:wat", "position": {"line": 1}}]}
	count(violations) == 1
	violations[_].rule == "gocheckcompilerdirectives"
}

test_detects_empty_generate_directive if {
	violations := gocheckcompilerdirectives.deny with input as {"comments": [{"text": "go:generate", "raw": "//go:generate", "position": {"line": 1}}]}
	count(violations) == 1
	violations[_].rule == "gocheckcompilerdirectives"
}

test_allows_known_directive if {
	violations := gocheckcompilerdirectives.deny with input as {"comments": [{"text": "go:generate stringer -type=Pill", "raw": "//go:generate stringer -type=Pill", "position": {"line": 1}}]}
	count(violations) == 0
}

test_ignores_regular_comment if {
	violations := gocheckcompilerdirectives.deny with input as {"comments": [{"text": "go:build linux", "raw": "// go:build linux", "position": {"line": 1}}]}
	count(violations) == 0
}
