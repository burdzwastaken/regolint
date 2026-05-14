package regolint.rules.test.tparallel_test

import data.regolint.rules.test.tparallel

test_detects_subtest_without_parallel if {
	violations := tparallel.deny with input as {"subtests": [{"name": "case", "function": "TestThing", "test_param": "t", "has_parallel": false, "position": {"line": 5}}]}
	count(violations) == 1
	violations[_].rule == "tparallel"
}

test_allows_subtest_with_parallel if {
	violations := tparallel.deny with input as {"subtests": [{"name": "case", "function": "TestThing", "test_param": "t", "has_parallel": true, "position": {"line": 5}}]}
	count(violations) == 0
}

test_detects_dynamic_named_subtest_without_parallel if {
	violations := tparallel.deny with input as {"subtests": [{"function": "TestThing", "test_param": "t", "has_parallel": false, "position": {"line": 5}}]}
	count(violations) == 1
}
