package regolint.rules.style.predeclared_test

import data.regolint.rules.style.predeclared

test_detects_function_shadowing_predeclared_identifier if {
	violations := predeclared.deny with input as {
		"functions": [{"name": "len", "position": {"line": 3}, "parameters": [], "returns": []}],
		"types": [],
		"variables": [],
		"constants": [],
	}
	count(violations) == 1
	violations[_].rule == "predeclared"
}

test_detects_parameter_shadowing_predeclared_identifier if {
	violations := predeclared.deny with input as {
		"functions": [{"name": "handle", "position": {"line": 3}, "parameters": [{"name": "error", "type": "string"}], "returns": []}],
		"types": [],
		"variables": [],
		"constants": [],
	}
	count(violations) == 1
}

test_allows_regular_identifiers if {
	violations := predeclared.deny with input as {
		"functions": [{"name": "handle", "position": {"line": 3}, "parameters": [{"name": "request", "type": "string"}], "returns": []}],
		"types": [{"name": "Repository", "methods": [], "position": {"line": 7}}],
		"variables": [{"name": "cache", "position": {"line": 9}}],
		"constants": [{"name": "defaultLimit", "position": {"line": 10}}],
	}
	count(violations) == 0
}
