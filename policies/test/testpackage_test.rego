package regolint.rules.test.testpackage_test

import data.regolint.rules.test.testpackage

test_detects_internal_test_package if {
	violations := testpackage.deny with input as {
		"file_path": "foo_test.go",
		"package": {"name": "foo"},
	}
	count(violations) == 1
	violations[_].rule == "testpackage"
}

test_allows_external_test_package if {
	violations := testpackage.deny with input as {
		"file_path": "foo_test.go",
		"package": {"name": "foo_test"},
	}
	count(violations) == 0
}

test_allows_non_test_file if {
	violations := testpackage.deny with input as {
		"file_path": "foo.go",
		"package": {"name": "foo"},
	}
	count(violations) == 0
}
