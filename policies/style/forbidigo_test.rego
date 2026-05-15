package regolint.rules.style.forbidigo_test

import data.regolint.rules.style.forbidigo

test_inactive_without_configuration if {
	violations := forbidigo.deny with input as {
		"functions": [{"name": "Release", "position": {"line": 4}}],
		"calls": [{"package": "fmt", "function": "Println", "position": {"line": 8}}],
	}
	count(violations) == 0
}

test_detects_default_forbidden_call if {
	violations := forbidigo.deny with input as {"calls": [{"package": "log", "function": "Fatal", "position": {"line": 8}}]}
	count(violations) == 1
}

test_detects_forbidden_identifier if {
	violations := forbidigo.deny with input as {
		"forbidden_identifiers": ["Debug"],
		"functions": [{"name": "Debug", "position": {"line": 4}}],
	}
	count(violations) == 1
	violations[_].rule == "forbidigo"
}

test_detects_forbidden_call if {
	violations := forbidigo.deny with input as {
		"forbidden_calls": ["fmt.Println"],
		"calls": [{"package": "fmt", "function": "Println", "position": {"line": 8}}],
	}
	count(violations) == 1
}

test_detects_rule_options_forbidden_call if {
	violations := forbidigo.deny with input as {
		"rule_options": {"forbidigo": {"calls": ["fmt.Println"]}},
		"calls": [{"package": "fmt", "function": "Println", "position": {"line": 8}}],
	}
	count(violations) == 1
}

test_detects_forbidden_receiver_call if {
	violations := forbidigo.deny with input as {
		"forbidden_calls": ["logger.Debug"],
		"calls": [{"receiver": "logger", "function": "Debug", "position": {"line": 8}}],
	}
	count(violations) == 1
}

test_detects_forbidden_string if {
	violations := forbidigo.deny with input as {
		"forbidden_strings": ["TODO"],
		"literals": [{"kind": "string", "value": "\"TODO\"", "position": {"line": 8}}],
	}
	count(violations) == 1
}
