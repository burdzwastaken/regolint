package regolint.rules.performance.mirror_test

import data.regolint.rules.performance.mirror

test_detects_bytes_call_with_byte_conversion if {
	violations := mirror.deny with input as {"calls": [{"package": "bytes", "function": "Contains", "args": ["[]byte(...)", "[]byte(...)"], "position": {"line": 8}}]}
	count(violations) == 1
	violations[_].rule == "mirror"
}

test_detects_strings_call_with_string_conversion if {
	violations := mirror.deny with input as {"calls": [{"package": "strings", "function": "Contains", "args": ["string(...)", "\"needle\""], "position": {"line": 8}}]}
	count(violations) == 1
}

test_allows_matching_package_and_argument_type if {
	violations := mirror.deny with input as {"calls": [{"package": "strings", "function": "Contains", "args": ["text", "needle"], "position": {"line": 8}}]}
	count(violations) == 0
}

test_allows_bytes_call_without_conversion if {
	violations := mirror.deny with input as {"calls": [{"package": "bytes", "function": "Contains", "args": ["data", "needle"], "position": {"line": 8}}]}
	count(violations) == 0
}
