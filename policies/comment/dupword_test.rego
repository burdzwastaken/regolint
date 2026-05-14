package regolint.rules.comment.dupword_test

import data.regolint.rules.comment.dupword

test_detects_duplicate_word_in_comment if {
	violations := dupword.deny with input as {
		"comments": [{"text": "the the value is cached", "position": {"line": 3}}],
		"literals": [],
	}
	count(violations) == 1
	violations[_].rule == "dupword"
}

test_detects_duplicate_word_in_string_literal if {
	violations := dupword.deny with input as {
		"comments": [],
		"literals": [{"kind": "string", "value": "\"go go now\"", "position": {"line": 5}}],
	}
	count(violations) == 1
}

test_allows_regular_text if {
	violations := dupword.deny with input as {
		"comments": [{"text": "the value is cached", "position": {"line": 3}}],
		"literals": [{"kind": "string", "value": "\"go now\"", "position": {"line": 5}}],
	}
	count(violations) == 0
}
