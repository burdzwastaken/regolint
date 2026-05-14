package regolint.rules.style.goprintffuncname_test

import data.regolint.rules.style.goprintffuncname

test_detects_printf_like_function_without_f_suffix if {
	violations := goprintffuncname.deny with input as {"functions": [{"name": "Log", "parameters": [{"name": "format", "type": "string"}, {"name": "args", "type": "...any"}], "position": {"line": 3}}]}
	count(violations) == 1
	violations[_].rule == "goprintffuncname"
}

test_allows_printf_like_function_with_f_suffix if {
	violations := goprintffuncname.deny with input as {"functions": [{"name": "Logf", "parameters": [{"name": "format", "type": "string"}, {"name": "args", "type": "...interface{}"}], "position": {"line": 3}}]}
	count(violations) == 0
}

test_allows_non_printf_function if {
	violations := goprintffuncname.deny with input as {"functions": [{"name": "Log", "parameters": [{"name": "message", "type": "string"}], "position": {"line": 3}}]}
	count(violations) == 0
}
