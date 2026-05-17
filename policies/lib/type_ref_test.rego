package regolint.lib.type_ref_test

import data.regolint.lib.type_ref

test_matches_legacy_type if {
	type_ref.matches({"type": "*store.Store"}, "*store.Store")
}

test_matches_semantic_identity if {
	type_ref.matches({"identity": "example.com/project/internal/store.Store"}, "example.com/project/internal/store.Store")
}

test_matches_package_path_and_name if {
	type_ref.matches(
		{
			"package_path": "example.com/project/internal/store",
			"name": "Store",
		},
		"example.com/project/internal/store.Store",
	)
}

test_pattern_matches_package_path if {
	type_ref.pattern_matches({"package_path": "example.com/project/internal/store"}, "/internal/")
}

test_is_named if {
	type_ref.is_named(
		{
			"kind": "named",
			"package_path": "database/sql",
			"name": "DB",
		},
		"database/sql", "DB",
	)
}

test_children_returns_elem_key_and_value if {
	children := type_ref.children({
		"elem": {"kind": "named", "name": "Elem"},
		"key": {"kind": "builtin", "name": "string"},
		"value": {"kind": "named", "name": "Value"},
	})
	count(children) == 3
}

test_exposes_nested_type_ref if {
	type_ref.exposes(
		{"type_ref": {
			"kind": "map",
			"key": {"kind": "builtin", "identity": "string"},
			"value": {
				"kind": "pointer",
				"elem": {
					"kind": "named",
					"identity": "example.com/project/internal/store.Store",
					"package_path": "example.com/project/internal/store",
					"name": "Store",
				},
			},
		}},
		["example.com/project/internal/store.Store"], [], [],
	)
}

test_allowed_nested_node_does_not_exempt_forbidden_sibling if {
	type_ref.exposes(
		{"type_ref": {
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
		}},
		[], ["/internal/"], ["example.com/project/internal/store.PublicSnapshot"],
	)
}

test_allowed_node_suppresses_same_candidate if {
	not type_ref.exposes(
		{"type_ref": {
			"kind": "named",
			"identity": "example.com/project/internal/store.PublicSnapshot",
			"package_path": "example.com/project/internal/store",
			"name": "PublicSnapshot",
		}},
		[], ["/internal/"], ["example.com/project/internal/store.PublicSnapshot"],
	)
}
