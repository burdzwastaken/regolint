package regolint.rules.style.iotamixing_test

import data.regolint.rules.style.iotamixing

test_detects_mixed_iota_const_block if {
	violations := iotamixing.deny with input as {
		"decl_groups": [{"kind": "const", "is_grouped": true, "block_id": 1, "position": {"line": 3}}],
		"constants": [
			{"name": "First", "block_id": 1, "uses_iota": true, "position": {"line": 4}},
			{"name": "Explicit", "block_id": 1, "uses_iota": false, "position": {"line": 5}},
		],
	}
	count(violations) == 1
	violations[_].rule == "iotamixing"
}

test_allows_iota_only_const_block if {
	violations := iotamixing.deny with input as {
		"decl_groups": [{"kind": "const", "is_grouped": true, "block_id": 1, "position": {"line": 3}}],
		"constants": [
			{"name": "First", "block_id": 1, "uses_iota": true, "position": {"line": 4}},
			{"name": "Second", "block_id": 1, "uses_iota": true, "position": {"line": 5}},
		],
	}
	count(violations) == 0
}

test_allows_non_iota_const_block if {
	violations := iotamixing.deny with input as {
		"decl_groups": [{"kind": "const", "is_grouped": true, "block_id": 1, "position": {"line": 3}}],
		"constants": [
			{"name": "First", "block_id": 1, "uses_iota": false, "position": {"line": 4}},
			{"name": "Second", "block_id": 1, "uses_iota": false, "position": {"line": 5}},
		],
	}
	count(violations) == 0
}
