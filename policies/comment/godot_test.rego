package regolint.rules.comment.godot_test

import data.regolint.rules.comment.godot

test_detects_comment_without_period if {
	violations := godot.deny with input as {"comments": [{
		"text": "Explains the branch",
		"position": {"line": 2},
	}]}
	count(violations) == 1
	violations[_].rule == "godot"
}

test_allows_comment_with_period if {
	violations := godot.deny with input as {"comments": [{
		"text": "Explains the branch.",
		"position": {"line": 2},
	}]}
	count(violations) == 0
}

test_ignores_nolint_directive if {
	violations := godot.deny with input as {"comments": [{
		"text": "nolint:godox",
		"position": {"line": 2},
	}]}
	count(violations) == 0
}
