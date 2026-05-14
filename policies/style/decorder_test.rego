package regolint.rules.style.decorder_test

import data.regolint.rules.style.decorder

test_detects_type_after_function_ordering if {
	violations := decorder.deny with input as {"declarations": [
		{"kind": "func", "name": "Run", "position": {"line": 3, "column": 1}},
		{"kind": "type", "name": "User", "position": {"line": 5, "column": 1}},
	]}
	count(violations) == 1
	violations[_].rule == "decorder"
}

test_allows_expected_order if {
	violations := decorder.deny with input as {"declarations": [
		{"kind": "import", "name": "fmt", "position": {"line": 3, "column": 1}},
		{"kind": "const", "name": "max", "position": {"line": 5, "column": 1}},
		{"kind": "var", "name": "value", "position": {"line": 7, "column": 1}},
		{"kind": "type", "name": "User", "position": {"line": 9, "column": 1}},
		{"kind": "func", "name": "Run", "position": {"line": 11, "column": 1}},
	]}
	count(violations) == 0
}
