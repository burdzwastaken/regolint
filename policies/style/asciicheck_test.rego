package regolint.rules.style.asciicheck_test

import data.regolint.rules.style.asciicheck

test_detects_non_ascii_function_name if {
	violations := asciicheck.deny with input as {
		"package": {"name": "example"},
		"functions": [{"name": "café", "position": {"line": 3}}],
		"types": [],
		"variables": [],
		"constants": [],
	}
	count(violations) == 1
	violations[_].rule == "asciicheck"
}

test_allows_ascii_identifiers if {
	violations := asciicheck.deny with input as {
		"package": {"name": "example"},
		"functions": [{"name": "serveHTTP", "position": {"line": 3}}],
		"types": [{"name": "Repository", "fields": [{"name": "ID", "position": {"line": 5}}], "methods": []}],
		"variables": [{"name": "cache", "position": {"line": 7}}],
		"constants": [{"name": "maxRetries", "position": {"line": 8}}],
	}
	count(violations) == 0
}
