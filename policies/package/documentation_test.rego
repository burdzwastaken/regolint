package regolint.rules.package.documentation_test

import data.regolint.rules.package.documentation

test_detects_undocumented_exported_type if {
	violations := documentation.deny with input as {
		"all_types": [{
			"name": "User",
			"is_exported": true,
			"doc": "",
			"position": {"line": 10},
		}],
		"all_functions": [],
	}
	count(violations) == 1
}

test_allows_documented_exported_type if {
	violations := documentation.deny with input as {
		"all_types": [{
			"name": "User",
			"is_exported": true,
			"doc": "User represents a system user.",
			"position": {"line": 10},
		}],
		"all_functions": [],
	}
	count(violations) == 0
}

test_ignores_unexported_types if {
	violations := documentation.deny with input as {
		"all_types": [{
			"name": "user",
			"is_exported": false,
			"doc": "",
			"position": {"line": 10},
		}],
		"all_functions": [],
	}
	count(violations) == 0
}

test_detects_undocumented_exported_function if {
	violations := documentation.deny with input as {
		"all_types": [],
		"all_functions": [{
			"name": "GetUser",
			"is_exported": true,
			"is_test": false,
			"comments": [],
			"position": {"line": 10},
		}],
	}
	count(violations) == 1
}

test_allows_documented_exported_function if {
	violations := documentation.deny with input as {
		"all_types": [],
		"all_functions": [{
			"name": "GetUser",
			"is_exported": true,
			"is_test": false,
			"comments": ["GetUser retrieves a user by ID."],
			"position": {"line": 10},
		}],
	}
	count(violations) == 0
}

test_ignores_test_functions if {
	violations := documentation.deny with input as {
		"all_types": [],
		"all_functions": [{
			"name": "TestGetUser",
			"is_exported": true,
			"is_test": true,
			"comments": [],
			"position": {"line": 10},
		}],
	}
	count(violations) == 0
}
