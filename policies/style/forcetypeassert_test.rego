package regolint.rules.style.forcetypeassert_test

import data.regolint.rules.style.forcetypeassert

test_detects_unchecked_type_assertion if {
	violations := forcetypeassert.deny with input as {"type_assertions": [{"expr": "value", "asserted_type": "string", "is_comma_ok": false, "position": {"line": 5}}]}
	count(violations) == 1
	violations[_].rule == "forcetypeassert"
}

test_allows_comma_ok_type_assertion if {
	violations := forcetypeassert.deny with input as {"type_assertions": [{"expr": "value", "asserted_type": "string", "is_comma_ok": true, "position": {"line": 5}}]}
	count(violations) == 0
}

test_ignores_type_switch_assertion if {
	violations := forcetypeassert.deny with input as {"type_assertions": [{"expr": "value", "asserted_type": "", "is_comma_ok": false, "position": {"line": 5}}]}
	count(violations) == 0
}
