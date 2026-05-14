package regolint.rules.style.nosprintfhostport_test

import data.regolint.rules.style.nosprintfhostport

test_detects_sprintf_host_port if {
	violations := nosprintfhostport.deny with input as {"calls": [{"package": "fmt", "function": "Sprintf", "args": ["\"%s:%d\"", "host", "port"], "position": {"line": 12}}]}
	count(violations) == 1
	violations[_].rule == "nosprintfhostport"
}

test_detects_string_port_format if {
	violations := nosprintfhostport.deny with input as {"calls": [{"package": "fmt", "function": "Sprintf", "args": ["\"%s:%s\"", "host", "port"], "position": {"line": 12}}]}
	count(violations) == 1
}

test_allows_non_host_port_sprintf if {
	violations := nosprintfhostport.deny with input as {"calls": [{"package": "fmt", "function": "Sprintf", "args": ["\"%s:%d\"", "name", "count"], "position": {"line": 12}}]}
	count(violations) == 0
}

test_allows_different_format_string if {
	violations := nosprintfhostport.deny with input as {"calls": [{"package": "fmt", "function": "Sprintf", "args": ["\"%s/%d\"", "host", "port"], "position": {"line": 12}}]}
	count(violations) == 0
}

test_allows_non_fmt_call if {
	violations := nosprintfhostport.deny with input as {"calls": [{"package": "log", "function": "Sprintf", "args": ["\"%s:%d\"", "host", "port"], "position": {"line": 12}}]}
	count(violations) == 0
}
