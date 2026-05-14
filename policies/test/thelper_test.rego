package regolint.rules.test.thelper_test

import data.regolint.rules.test.thelper

test_detects_helper_without_helper_call if {
	violations := thelper.deny with input as {
		"functions": [{"name": "assertThing", "parameters": [{"name": "t", "type": "*testing.T"}], "position": {"line": 4}}],
		"calls": [],
	}
	count(violations) == 1
	violations[_].rule == "thelper"
}

test_allows_helper_with_helper_call if {
	violations := thelper.deny with input as {
		"functions": [{"name": "assertThing", "parameters": [{"name": "t", "type": "*testing.T"}], "position": {"line": 4}}],
		"calls": [{"receiver": "t", "function": "Helper", "in_function": "assertThing", "position": {"line": 5}}],
	}
	count(violations) == 0
}

test_allows_test_entrypoint if {
	violations := thelper.deny with input as {
		"functions": [{"name": "TestThing", "is_test": true, "parameters": [{"name": "t", "type": "*testing.T"}], "position": {"line": 4}}],
		"calls": [],
	}
	count(violations) == 0
}

test_allows_non_helper_name if {
	violations := thelper.deny with input as {
		"functions": [{"name": "buildThing", "parameters": [{"name": "t", "type": "*testing.T"}], "position": {"line": 4}}],
		"calls": [],
	}
	count(violations) == 0
}
