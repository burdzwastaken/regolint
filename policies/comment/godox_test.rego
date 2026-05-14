package regolint.rules.comment.godox_test

import data.regolint.rules.comment.godox

test_detects_todo_comment if {
	violations := godox.deny with input as {"comments": [{
		"text": "TODO: wire package facts",
		"position": {"line": 2},
	}]}
	count(violations) == 1
	violations[_].rule == "godox"
}

test_allows_regular_comment if {
	violations := godox.deny with input as {"comments": [{
		"text": "Explains why this branch exists.",
		"position": {"line": 2},
	}]}
	count(violations) == 0
}
