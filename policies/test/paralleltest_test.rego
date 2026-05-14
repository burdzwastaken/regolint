package regolint.rules.test.paralleltest_test

import data.regolint.rules.test.paralleltest

test_detects_test_without_parallel if {
	violations := paralleltest.deny with input as {
		"functions": [{"name": "TestThing", "is_test": true, "parameters": [{"name": "t", "type": "*testing.T"}], "position": {"line": 4}}],
		"calls": [],
	}
	count(violations) == 1
	violations[_].rule == "paralleltest"
}

test_allows_test_with_parallel if {
	violations := paralleltest.deny with input as {
		"functions": [{"name": "TestThing", "is_test": true, "parameters": [{"name": "t", "type": "*testing.T"}], "position": {"line": 4}}],
		"calls": [{"receiver": "t", "function": "Parallel", "in_function": "TestThing", "position": {"line": 5}}],
	}
	count(violations) == 0
}

test_ignores_parallel_call_inside_subtest_callback if {
	violations := paralleltest.deny with input as {
		"functions": [{"name": "TestThing", "is_test": true, "parameters": [{"name": "t", "type": "*testing.T"}], "position": {"line": 4}}],
		"calls": [{"receiver": "t", "function": "Parallel", "in_function": "TestThing", "in_func_lit": true, "position": {"line": 6}}],
	}
	count(violations) == 1
}

test_ignores_benchmarks_and_examples if {
	violations := paralleltest.deny with input as {
		"functions": [
			{"name": "BenchmarkThing", "is_test": true, "parameters": [{"name": "b", "type": "*testing.B"}], "position": {"line": 4}},
			{"name": "ExampleThing", "is_test": true, "parameters": [], "position": {"line": 8}},
		],
		"calls": [],
	}
	count(violations) == 0
}

test_ignores_non_test_function if {
	violations := paralleltest.deny with input as {
		"functions": [{"name": "helper", "parameters": [{"name": "t", "type": "*testing.T"}], "position": {"line": 4}}],
		"calls": [],
	}
	count(violations) == 0
}
