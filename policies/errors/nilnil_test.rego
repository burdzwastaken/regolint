package regolint.rules.errors.nilnil_test

import data.regolint.rules.errors.nilnil

test_detects_nil_nil_for_nillable_results if {
	violations := nilnil.deny with input as {
		"functions": [{"name": "Find", "returns": [{"type": "*User"}, {"type": "error"}], "position": {"line": 4}}],
		"returns": [{"function": "Find", "results": ["nil", "nil"], "position": {"line": 6}}],
	}
	count(violations) == 1
	violations[_].rule == "nilnil"
}

test_allows_non_nil_error_return if {
	violations := nilnil.deny with input as {
		"functions": [{"name": "Find", "returns": [{"type": "*User"}, {"type": "error"}], "position": {"line": 4}}],
		"returns": [{"function": "Find", "results": ["nil", "err"], "position": {"line": 6}}],
	}
	count(violations) == 0
}

test_allows_non_nillable_results if {
	violations := nilnil.deny with input as {
		"functions": [{"name": "Lookup", "returns": [{"type": "int"}, {"type": "error"}], "position": {"line": 4}}],
		"returns": [{"function": "Lookup", "results": ["nil", "nil"], "position": {"line": 6}}],
	}
	count(violations) == 0
}

test_allows_single_nil_result if {
	violations := nilnil.deny with input as {
		"functions": [{"name": "Err", "returns": [{"type": "error"}], "position": {"line": 4}}],
		"returns": [{"function": "Err", "results": ["nil"], "position": {"line": 6}}],
	}
	count(violations) == 0
}

test_disambiguates_same_named_methods_by_receiver if {
	violations := nilnil.deny with input as {
		"functions": [
			{"name": "Read", "receiver": "*A", "returns": [{"type": "*User"}, {"type": "error"}], "position": {"line": 4}},
			{"name": "Read", "receiver": "B", "returns": [{"type": "int"}, {"type": "error"}], "position": {"line": 8}},
		],
		"returns": [{"function": "Read", "receiver": "B", "results": ["nil", "nil"], "position": {"line": 10}}],
	}
	count(violations) == 0
}
