package regolint.rules.imports.exptostd_test

import data.regolint.rules.imports.exptostd

test_detects_exp_slices_import if {
	violations := exptostd.deny with input as {"imports": [{"path": "golang.org/x/exp/slices", "position": {"line": 3}}]}
	count(violations) == 1
	violations[_].rule == "exptostd"
}

test_allows_stdlib_slices_import if {
	violations := exptostd.deny with input as {"imports": [{"path": "slices", "position": {"line": 3}}]}
	count(violations) == 0
}

test_allows_unrelated_exp_import if {
	violations := exptostd.deny with input as {"imports": [{"path": "golang.org/x/exp/constraints", "position": {"line": 3}}]}
	count(violations) == 0
}
