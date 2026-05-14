package regolint.rules.style.usestdlibvars_test

import data.regolint.rules.style.usestdlibvars

test_detects_http_method_literal if {
	violations := usestdlibvars.deny with input as {"literals": [{"kind": "string", "value": "\"GET\"", "position": {"line": 8}}]}
	count(violations) == 1
	violations[_].rule == "usestdlibvars"
}

test_detects_top_level_constant_value if {
	violations := usestdlibvars.deny with input as {"constants": [{"name": "method", "value": "\"POST\"", "position": {"line": 4}}]}
	count(violations) == 1
}

test_detects_header_literal if {
	violations := usestdlibvars.deny with input as {"literals": [{"kind": "string", "value": "\"Content-Type\"", "position": {"line": 8}}]}
	count(violations) == 1
}

test_allows_regular_string_literal if {
	violations := usestdlibvars.deny with input as {"literals": [{"kind": "string", "value": "\"custom\"", "position": {"line": 8}}]}
	count(violations) == 0
}
