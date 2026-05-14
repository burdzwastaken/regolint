package regolint.rules.style.interfacebloat_test

import data.regolint.rules.style.interfacebloat

methods := [
	{"name": "A"},
	{"name": "B"},
	{"name": "C"},
	{"name": "D"},
	{"name": "E"},
	{"name": "F"},
	{"name": "G"},
	{"name": "H"},
	{"name": "I"},
	{"name": "J"},
	{"name": "K"},
]

test_detects_large_interface if {
	violations := interfacebloat.deny with input as {"types": [{
		"name": "Huge",
		"kind": "interface",
		"methods": methods,
		"position": {"line": 3},
	}]}
	count(violations) == 1
	violations[_].rule == "interfacebloat"
}

test_allows_small_interface if {
	violations := interfacebloat.deny with input as {"types": [{
		"name": "Small",
		"kind": "interface",
		"methods": array.slice(methods, 0, 2),
		"position": {"line": 3},
	}]}
	count(violations) == 0
}
