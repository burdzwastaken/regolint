package regolint.rules.structs.tags_test

import data.regolint.rules.structs.tags

test_detects_missing_json_tag if {
	violations := tags.deny with input as {"types": [{
		"name": "User",
		"kind": "struct",
		"is_exported": true,
		"fields": [{
			"name": "Name",
			"is_exported": true,
			"is_embedded": false,
			"tags": "",
			"position": {"line": 5},
		}],
		"position": {"line": 4},
	}]}
	count(violations) == 1
}

test_allows_field_with_json_tag if {
	violations := tags.deny with input as {"types": [{
		"name": "User",
		"kind": "struct",
		"is_exported": true,
		"fields": [{
			"name": "Name",
			"is_exported": true,
			"is_embedded": false,
			"tags": "json:\"name\"",
			"position": {"line": 5},
		}],
		"position": {"line": 4},
	}]}
	count(violations) == 0
}

test_ignores_unexported_fields if {
	violations := tags.deny with input as {"types": [{
		"name": "User",
		"kind": "struct",
		"is_exported": true,
		"fields": [{
			"name": "name",
			"is_exported": false,
			"is_embedded": false,
			"tags": "",
			"position": {"line": 5},
		}],
		"position": {"line": 4},
	}]}
	count(violations) == 0
}

test_ignores_unexported_structs if {
	violations := tags.deny with input as {"types": [{
		"name": "user",
		"kind": "struct",
		"is_exported": false,
		"fields": [{
			"name": "Name",
			"is_exported": true,
			"is_embedded": false,
			"tags": "",
			"position": {"line": 5},
		}],
		"position": {"line": 4},
	}]}
	count(violations) == 0
}

test_ignores_embedded_fields if {
	violations := tags.deny with input as {"types": [{
		"name": "User",
		"kind": "struct",
		"is_exported": true,
		"fields": [{
			"name": "BaseModel",
			"is_exported": true,
			"is_embedded": true,
			"tags": "",
			"position": {"line": 5},
		}],
		"position": {"line": 4},
	}]}
	count(violations) == 0
}
