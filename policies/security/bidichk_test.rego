package regolint.rules.security.bidichk_test

import data.regolint.rules.security.bidichk

test_detects_bidi_in_comment if {
	violations := bidichk.deny with input as {"comments": [{"text": "safe \u202e unsafe", "position": {"line": 3}}]}
	count(violations) == 1
	violations[_].rule == "bidichk"
}

test_detects_bidi_in_identifier if {
	violations := bidichk.deny with input as {"file_path": "main.go", "package": {"name": "main"}, "functions": [{"name": "safe\u202e", "position": {"line": 5}}]}
	count(violations) == 1
	violations[_].rule == "bidichk"
}

test_detects_bidi_in_top_level_constant_value if {
	violations := bidichk.deny with input as {"constants": [{"name": "Message", "value": "\"safe\u202e\"", "position": {"line": 4}}]}
	count(violations) == 1
	violations[_].rule == "bidichk"
}

test_allows_plain_text if {
	violations := bidichk.deny with input as {"comments": [{"text": "plain comment", "position": {"line": 3}}], "literals": [{"kind": "string", "value": "plain", "position": {"line": 4}}]}
	count(violations) == 0
}
