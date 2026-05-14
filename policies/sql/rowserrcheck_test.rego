package regolint.rules.sql.rowserrcheck_test

import data.regolint.rules.sql.rowserrcheck

test_detects_missing_rows_err_check if {
	violations := rowserrcheck.deny with input as {
		"resource_acquires": [{"kind": "sql_rows", "target": "rows", "source": "db.Query", "in_function": "query", "position": {"line": 10, "column": 10}}],
		"resource_errs": [],
	}
	count(violations) == 1
	violations[_].rule == "rowserrcheck"
}

test_allows_rows_err_check if {
	violations := rowserrcheck.deny with input as {
		"resource_acquires": [{"kind": "sql_rows", "target": "rows", "source": "db.Query", "in_function": "query", "position": {"line": 10, "column": 10}}],
		"resource_errs": [{"target": "rows", "is_checked": true, "in_function": "query", "position": {"line": 20, "column": 5}}],
	}
	count(violations) == 0
}

test_detects_unchecked_rows_err_call if {
	violations := rowserrcheck.deny with input as {
		"resource_acquires": [{"kind": "sql_rows", "target": "rows", "source": "db.Query", "in_function": "query", "position": {"line": 10, "column": 10}}],
		"resource_errs": [{"target": "rows", "is_checked": false, "in_function": "query", "position": {"line": 20, "column": 5}}],
	}
	count(violations) == 1
}

test_ignores_err_check_before_query if {
	violations := rowserrcheck.deny with input as {
		"resource_acquires": [{"kind": "sql_rows", "target": "rows", "source": "db.Query", "in_function": "query", "position": {"line": 10, "column": 10}}],
		"resource_errs": [{"target": "rows", "is_checked": true, "in_function": "query", "position": {"line": 9, "column": 5}}],
	}
	count(violations) == 1
}

test_ignores_err_check_after_reacquire if {
	violations := rowserrcheck.deny with input as {
		"resource_acquires": [
			{"kind": "sql_rows", "target": "rows", "source": "db.Query", "in_function": "query", "position": {"line": 10, "column": 10}},
			{"kind": "sql_rows", "target": "rows", "source": "db.Query", "in_function": "query", "position": {"line": 15, "column": 10}},
		],
		"resource_errs": [{"target": "rows", "is_checked": true, "in_function": "query", "position": {"line": 20, "column": 5}}],
	}
	count(violations) == 1
}

test_ignores_non_rows_resources if {
	violations := rowserrcheck.deny with input as {
		"resource_acquires": [{"kind": "sql_stmt", "target": "stmt", "source": "db.Prepare", "in_function": "query", "position": {"line": 10, "column": 10}}],
		"resource_errs": [],
	}
	count(violations) == 0
}
