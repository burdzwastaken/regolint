package regolint.rules.imports.banned_test

import data.regolint.rules.imports.banned

test_detects_unsafe_import if {
	violations := banned.deny with input as {"imports": [{"path": "unsafe", "position": {"line": 5, "column": 2}}]}
	count(violations) == 1
}

test_allows_safe_imports if {
	violations := banned.deny with input as {"imports": [
		{"path": "fmt", "position": {"line": 5}},
		{"path": "os", "position": {"line": 6}},
	]}
	count(violations) == 0
}

test_detects_multiple_banned if {
	violations := banned.deny with input as {"imports": [
		{"path": "fmt", "position": {"line": 5}},
		{"path": "unsafe", "position": {"line": 6}},
	]}
	count(violations) == 1
}
