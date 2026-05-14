package regolint.rules.test.testableexamples_test

import data.regolint.rules.test.testableexamples

test_detects_example_without_output if {
	violations := testableexamples.deny with input as {
		"functions": [{"name": "ExampleThing", "line_count": 4, "position": {"line": 10}}],
		"comments": [],
	}
	count(violations) == 1
	violations[_].rule == "testableexamples"
}

test_allows_example_with_output if {
	violations := testableexamples.deny with input as {
		"functions": [{"name": "ExampleThing", "line_count": 4, "position": {"line": 10}}],
		"comments": [{"text": "Output:", "position": {"line": 13}}],
	}
	count(violations) == 0
}

test_detects_output_after_example_body if {
	violations := testableexamples.deny with input as {
		"functions": [{"name": "ExampleThing", "line_count": 4, "position": {"line": 10}}],
		"comments": [{"text": "Output:", "position": {"line": 14}}],
	}
	count(violations) == 1
}

test_allows_example_with_unordered_output if {
	violations := testableexamples.deny with input as {
		"functions": [{"name": "ExampleThing", "line_count": 4, "position": {"line": 10}}],
		"comments": [{"text": "Unordered output:", "position": {"line": 13}}],
	}
	count(violations) == 0
}

test_allows_non_example_function if {
	violations := testableexamples.deny with input as {
		"functions": [{"name": "TestThing", "line_count": 4, "position": {"line": 10}}],
		"comments": [],
	}
	count(violations) == 0
}
