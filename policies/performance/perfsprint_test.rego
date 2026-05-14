package regolint.rules.performance.perfsprint_test

import data.regolint.rules.performance.perfsprint

test_detects_simple_string_sprintf if {
	violations := perfsprint.deny with input as {"calls": [{"package": "fmt", "function": "Sprintf", "args": ["\"%s\"", "name"], "position": {"line": 8}}]}
	count(violations) == 1
	violations[_].rule == "perfsprint"
}

test_detects_simple_integer_sprintf if {
	violations := perfsprint.deny with input as {"calls": [{"package": "fmt", "function": "Sprintf", "args": ["\"%d\"", "count"], "position": {"line": 8}}]}
	count(violations) == 1
}

test_detects_sprint_wrapping_sprintf if {
	violations := perfsprint.deny with input as {"calls": [{"package": "fmt", "function": "Sprint", "args": ["fmt.Sprintf(...)"], "position": {"line": 8}}]}
	count(violations) == 1
}

test_allows_complex_sprintf if {
	violations := perfsprint.deny with input as {"calls": [{"package": "fmt", "function": "Sprintf", "args": ["\"hello %s\"", "name"], "position": {"line": 8}}]}
	count(violations) == 0
}
