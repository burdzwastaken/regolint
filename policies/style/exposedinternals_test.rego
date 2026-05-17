package regolint.rules.style.exposedinternals_test

import data.regolint.rules.style.exposedinternals

test_inactive_without_configuration if {
	violations := exposedinternals.deny with input as {"functions": [{
		"name": "NewService",
		"is_exported": true,
		"parameters": [{"name": "store", "type": "*internal.Store"}],
	}]}
	count(violations) == 0
}

test_detects_exported_function_parameter if {
	violations := exposedinternals.deny with input as {
		"rule_options": {"exposedinternals": {"forbidden_type_patterns": ["^\\*?internal\\."]}},
		"functions": [{
			"name": "NewService",
			"is_exported": true,
			"parameters": [{"name": "store", "type": "*internal.Store"}],
			"position": {"line": 10},
		}],
	}
	count(violations) == 1
	violations[_].rule == "exposedinternals"
}

test_detects_exported_function_return if {
	violations := exposedinternals.deny with input as {
		"rule_options": {"exposedinternals": {"forbidden_types": ["internal.Store"]}},
		"functions": [{
			"name": "Store",
			"is_exported": true,
			"returns": [{"type": "internal.Store"}],
			"position": {"line": 12},
		}],
	}
	count(violations) == 1
}

test_allows_configured_type if {
	violations := exposedinternals.deny with input as {
		"rule_options": {"exposedinternals": {
			"forbidden_type_patterns": ["^internal\\."],
			"allowed_types": ["internal.PublicCompat"],
		}},
		"functions": [{
			"name": "Compat",
			"is_exported": true,
			"returns": [{"type": "internal.PublicCompat"}],
		}],
	}
	count(violations) == 0
}

test_ignores_unexported_function if {
	violations := exposedinternals.deny with input as {
		"rule_options": {"exposedinternals": {"forbidden_type_patterns": ["^\\*?internal\\."]}},
		"functions": [{
			"name": "newService",
			"is_exported": false,
			"parameters": [{"name": "store", "type": "*internal.Store"}],
		}],
	}
	count(violations) == 0
}

test_detects_exported_field if {
	violations := exposedinternals.deny with input as {
		"rule_options": {"exposedinternals": {"forbidden_types": ["internal.Store"]}},
		"types": [{
			"name": "Service",
			"is_exported": true,
			"fields": [{"name": "Store", "type": "internal.Store", "is_exported": true, "position": {"line": 20}}],
		}],
	}
	count(violations) == 1
}

test_ignores_unexported_fields_and_types if {
	violations := exposedinternals.deny with input as {
		"rule_options": {"exposedinternals": {"forbidden_types": ["internal.Store"]}},
		"types": [
			{
				"name": "Service",
				"is_exported": true,
				"fields": [{"name": "store", "type": "internal.Store", "is_exported": false}],
			},
			{
				"name": "service",
				"is_exported": false,
				"fields": [{"name": "Store", "type": "internal.Store", "is_exported": true}],
			},
		],
	}
	count(violations) == 0
}

test_allows_configured_function if {
	violations := exposedinternals.deny with input as {
		"rule_options": {"exposedinternals": {
			"forbidden_types": ["internal.Store"],
			"allowed_functions": ["Store"],
		}},
		"functions": [{
			"name": "Store",
			"is_exported": true,
			"returns": [{"type": "internal.Store"}],
		}],
	}
	count(violations) == 0
}

test_matches_type_identity if {
	violations := exposedinternals.deny with input as {
		"rule_options": {"exposedinternals": {"forbidden_types": ["example.com/project/internal/store.Store"]}},
		"functions": [{
			"name": "NewService",
			"is_exported": true,
			"parameters": [{"name": "store", "type": "*store.Store", "type_identity": "example.com/project/internal/store.Store"}],
		}],
	}
	count(violations) == 1
}

test_uses_legacy_configuration if {
	violations := exposedinternals.deny with input as {
		"exposed_internal_type_patterns": ["/internal/"],
		"functions": [{
			"name": "NewService",
			"is_exported": true,
			"parameters": [{"name": "store", "type": "*store.Store", "type_identity": "example.com/project/internal/store.Store"}],
		}],
	}
	count(violations) == 1
}

test_detects_nested_type_ref_parameter if {
	violations := exposedinternals.deny with input as {
		"rule_options": {"exposedinternals": {"forbidden_types": ["example.com/project/internal/store.Store"]}},
		"functions": [{
			"name": "NewService",
			"is_exported": true,
			"parameters": [{
				"name": "stores",
				"type": "map[string]*store.Store",
				"type_ref": {
					"kind": "map",
					"key": {"kind": "builtin", "identity": "string", "name": "string"},
					"value": {
						"kind": "pointer",
						"elem": {
							"kind": "named",
							"identity": "example.com/project/internal/store.Store",
							"package_path": "example.com/project/internal/store",
							"name": "Store",
						},
					},
				},
			}],
		}],
	}
	count(violations) == 1
}

test_detects_nested_type_ref_package_pattern if {
	violations := exposedinternals.deny with input as {
		"rule_options": {"exposedinternals": {"forbidden_type_patterns": ["/internal/"]}},
		"functions": [{
			"name": "Stores",
			"is_exported": true,
			"returns": [{
				"type": "[]store.Store",
				"type_ref": {
					"kind": "slice",
					"elem": {
						"kind": "named",
						"identity": "example.com/project/internal/store.Store",
						"package_path": "example.com/project/internal/store",
						"name": "Store",
					},
				},
			}],
		}],
	}
	count(violations) == 1
}

test_allowed_nested_type_ref_does_not_exempt_forbidden_sibling if {
	violations := exposedinternals.deny with input as {
		"rule_options": {"exposedinternals": {
			"forbidden_type_patterns": ["/internal/"],
			"allowed_types": ["example.com/project/internal/store.PublicSnapshot"],
		}},
		"functions": [{
			"name": "Stores",
			"is_exported": true,
			"returns": [{
				"type": "map[store.PublicSnapshot]store.Store",
				"type_ref": {
					"kind": "map",
					"key": {
						"kind": "named",
						"identity": "example.com/project/internal/store.PublicSnapshot",
						"package_path": "example.com/project/internal/store",
						"name": "PublicSnapshot",
					},
					"value": {
						"kind": "named",
						"identity": "example.com/project/internal/store.Store",
						"package_path": "example.com/project/internal/store",
						"name": "Store",
					},
				},
			}],
		}],
	}
	count(violations) == 1
}
