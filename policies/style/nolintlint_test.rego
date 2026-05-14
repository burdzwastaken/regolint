package regolint.rules.style.nolintlint_test

import data.regolint.rules.style.nolintlint

test_detects_unspecific_nolint if {
	violations := nolintlint.deny with input as {"nolints": [{"line": 5, "rules": []}]}
	count(violations) == 1
	violations[_].rule == "nolintlint"
}

test_allows_rule_specific_nolint if {
	violations := nolintlint.deny with input as {"nolints": [{"line": 5, "rules": ["lll"]}]}
	count(violations) == 0
}

test_detects_missing_rules_field if {
	violations := nolintlint.deny with input as {"nolints": [{"line": 5}]}
	count(violations) == 1
}
