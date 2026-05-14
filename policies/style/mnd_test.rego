package regolint.rules.style.mnd_test

import data.regolint.rules.style.mnd

test_detects_magic_number if {
	violations := mnd.deny with input as {"literals": [{
		"kind": "int",
		"value": "42",
		"in_function": "score",
		"position": {"line": 4},
	}]}
	count(violations) == 1
	violations[_].rule == "mnd"
}

test_allows_common_numbers if {
	violations := mnd.deny with input as {"literals": [
		{"kind": "int", "value": "0", "position": {"line": 4}},
		{"kind": "int", "value": "1", "position": {"line": 5}},
		{"kind": "float", "value": "2.0", "position": {"line": 6}},
	]}
	count(violations) == 0
}

test_ignores_string_literals if {
	violations := mnd.deny with input as {"literals": [{
		"kind": "string",
		"value": "42",
		"position": {"line": 4},
	}]}
	count(violations) == 0
}

test_detects_negative_magic_number if {
	violations := mnd.deny with input as {"literals": [{
		"kind": "int",
		"value": "-42",
		"position": {"line": 4},
	}]}
	count(violations) == 1
}
