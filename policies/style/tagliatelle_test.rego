package regolint.rules.style.tagliatelle_test

import data.regolint.rules.style.tagliatelle

test_detects_pascal_json_tag if {
	violations := tagliatelle.deny with input as {"types": [{
		"name": "User",
		"kind": "struct",
		"fields": [{
			"name": "DisplayName",
			"is_embedded": false,
			"tags": "json:\"DisplayName\"",
			"position": {"line": 5},
		}],
	}]}
	count(violations) == 1
	violations[_].rule == "tagliatelle"
}

test_detects_non_snake_yaml_tag if {
	violations := tagliatelle.deny with input as {"types": [{
		"name": "User",
		"kind": "struct",
		"fields": [{
			"name": "DisplayName",
			"is_embedded": false,
			"tags": "yaml:\"displayName\"",
			"position": {"line": 5},
		}],
	}]}
	count(violations) == 1
}

test_allows_snake_case_tags if {
	violations := tagliatelle.deny with input as {"types": [{
		"name": "User",
		"kind": "struct",
		"fields": [{
			"name": "DisplayName",
			"is_embedded": false,
			"tags": "json:\"display_name,omitempty\" yaml:\"display_name\"",
			"position": {"line": 5},
		}],
	}]}
	count(violations) == 0
}

test_allows_special_schema_tag if {
	violations := tagliatelle.deny with input as {"types": [{
		"name": "Document",
		"kind": "struct",
		"fields": [{
			"name": "Schema",
			"is_embedded": false,
			"tags": "json:\"$schema\"",
			"position": {"line": 5},
		}],
	}]}
	count(violations) == 0
}

test_ignores_dash_tag if {
	violations := tagliatelle.deny with input as {"types": [{
		"name": "User",
		"kind": "struct",
		"fields": [{
			"name": "Secret",
			"is_embedded": false,
			"tags": "json:\"-\"",
			"position": {"line": 5},
		}],
	}]}
	count(violations) == 0
}

test_checks_embedded_field_tags if {
	violations := tagliatelle.deny with input as {"types": [{
		"name": "User",
		"kind": "struct",
		"fields": [{
			"name": "BaseModel",
			"is_embedded": true,
			"tags": "json:\"baseModel\"",
			"position": {"line": 5},
		}],
	}]}
	count(violations) == 1
}

test_ignores_tag_name_substrings if {
	violations := tagliatelle.deny with input as {"types": [{
		"name": "User",
		"kind": "struct",
		"fields": [{
			"name": "DisplayName",
			"is_embedded": false,
			"tags": "myjson:\"DisplayName\"",
			"position": {"line": 5},
		}],
	}]}
	count(violations) == 0
}
