package regolint.rules.style.recvcheck_test

import data.regolint.rules.style.recvcheck

test_detects_mixed_receivers if {
	violations := recvcheck.deny with input as {"functions": [
		{"name": "Save", "receiver": "Repository", "position": {"line": 3}},
		{"name": "Load", "receiver": "*Repository", "position": {"line": 7}},
	]}
	count(violations) == 1
	violations[_].rule == "recvcheck"
}

test_allows_consistent_receivers if {
	violations := recvcheck.deny with input as {"functions": [
		{"name": "Save", "receiver": "*Repository", "position": {"line": 3}},
		{"name": "Load", "receiver": "*Repository", "position": {"line": 7}},
	]}
	count(violations) == 0
}
