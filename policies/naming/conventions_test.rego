package regolint.rules.naming.conventions_test

import data.regolint.rules.naming.conventions

test_detects_repository_without_suffix if {
	violations := conventions.deny with input as {"types": [{
		"name": "UserData",
		"kind": "interface",
		"methods": [
			{"name": "Get"},
			{"name": "Create"},
			{"name": "Update"},
		],
		"position": {"line": 10},
	}]}
	count(violations) == 1
}

test_allows_repository_with_suffix if {
	violations := conventions.deny with input as {"types": [{
		"name": "UserRepository",
		"kind": "interface",
		"methods": [
			{"name": "Get"},
			{"name": "Create"},
			{"name": "Delete"},
		],
		"position": {"line": 10},
	}]}
	count(violations) == 0
}

test_allows_store_suffix if {
	violations := conventions.deny with input as {"types": [{
		"name": "UserStore",
		"kind": "interface",
		"methods": [
			{"name": "Get"},
			{"name": "Create"},
		],
		"position": {"line": 10},
	}]}
	count(violations) == 0
}

test_ignores_non_repository_interfaces if {
	violations := conventions.deny with input as {"types": [{
		"name": "Logger",
		"kind": "interface",
		"methods": [
			{"name": "Info"},
			{"name": "Error"},
		],
		"position": {"line": 10},
	}]}
	count(violations) == 0
}

test_ignores_structs if {
	violations := conventions.deny with input as {"types": [{
		"name": "UserData",
		"kind": "struct",
		"methods": [
			{"name": "Get"},
			{"name": "Create"},
		],
		"position": {"line": 10},
	}]}
	count(violations) == 0
}
