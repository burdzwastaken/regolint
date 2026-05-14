package regolint.rules.style.embeddedstructfieldcheck_test

import data.regolint.rules.style.embeddedstructfieldcheck

test_detects_embedded_field_after_regular_field if {
	violations := embeddedstructfieldcheck.deny with input as {"types": [{
		"name": "User",
		"kind": "struct",
		"fields": [
			{
				"name": "Name",
				"is_embedded": false,
				"position": {"line": 5},
			},
			{
				"name": "BaseModel",
				"is_embedded": true,
				"position": {"line": 6},
			},
		],
	}]}
	count(violations) == 1
	violations[_].rule == "embeddedstructfieldcheck"
}

test_allows_embedded_field_before_regular_field if {
	violations := embeddedstructfieldcheck.deny with input as {"types": [{
		"name": "User",
		"kind": "struct",
		"fields": [
			{
				"name": "BaseModel",
				"is_embedded": true,
				"position": {"line": 5},
			},
			{
				"name": "Name",
				"is_embedded": false,
				"position": {"line": 6},
			},
		],
	}]}
	count(violations) == 0
}

test_detects_same_line_embedded_field_after_regular_field if {
	violations := embeddedstructfieldcheck.deny with input as {"types": [{
		"name": "User",
		"kind": "struct",
		"fields": [
			{
				"name": "Name",
				"is_embedded": false,
				"position": {"line": 5, "column": 16},
			},
			{
				"name": "BaseModel",
				"is_embedded": true,
				"position": {"line": 5, "column": 29},
			},
		],
	}]}
	count(violations) == 1
}

test_allows_struct_without_embedded_fields if {
	violations := embeddedstructfieldcheck.deny with input as {"types": [{
		"name": "User",
		"kind": "struct",
		"fields": [{
			"name": "Name",
			"is_embedded": false,
			"position": {"line": 5},
		}],
	}]}
	count(violations) == 0
}
