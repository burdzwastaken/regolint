package regolint.rules.sql.sqlclosecheck_test

import data.regolint.rules.sql.sqlclosecheck

test_detects_unclosed_rows if {
	violations := sqlclosecheck.deny with input as {
		"resource_acquires": [{"kind": "sql_rows", "target": "rows", "source": "db.Query", "in_function": "query", "position": {"line": 10, "column": 10}}],
		"resource_closes": [],
	}
	count(violations) == 1
	violations[_].rule == "sqlclosecheck"
}

test_detects_unclosed_stmt if {
	violations := sqlclosecheck.deny with input as {
		"resource_acquires": [{"kind": "sql_stmt", "target": "stmt", "source": "db.Prepare", "in_function": "query", "position": {"line": 10, "column": 10}}],
		"resource_closes": [],
	}
	count(violations) == 1
}

test_allows_closed_rows if {
	violations := sqlclosecheck.deny with input as {
		"resource_acquires": [{"kind": "sql_rows", "target": "rows", "source": "db.Query", "in_function": "query", "position": {"line": 10, "column": 10}}],
		"resource_closes": [{"target": "rows", "is_defer": true, "in_function": "query", "position": {"line": 11, "column": 2}}],
	}
	count(violations) == 0
}

test_ignores_close_before_acquire if {
	violations := sqlclosecheck.deny with input as {
		"resource_acquires": [{"kind": "sql_stmt", "target": "stmt", "source": "db.Prepare", "in_function": "query", "position": {"line": 10, "column": 10}}],
		"resource_closes": [{"target": "stmt", "is_defer": true, "in_function": "query", "position": {"line": 9, "column": 2}}],
	}
	count(violations) == 1
}

test_ignores_http_resources if {
	violations := sqlclosecheck.deny with input as {
		"resource_acquires": [{"kind": "http_response", "target": "resp", "source": "http.Get", "in_function": "fetch", "position": {"line": 10, "column": 10}}],
		"resource_closes": [],
	}
	count(violations) == 0
}

test_ignores_close_after_reacquire if {
	violations := sqlclosecheck.deny with input as {
		"resource_acquires": [
			{"kind": "sql_rows", "target": "rows", "source": "db.Query", "in_function": "query", "position": {"line": 10, "column": 10}},
			{"kind": "sql_rows", "target": "rows", "source": "db.Query", "in_function": "query", "position": {"line": 15, "column": 10}},
		],
		"resource_closes": [{"target": "rows", "is_defer": true, "in_function": "query", "position": {"line": 20, "column": 2}}],
	}
	count(violations) == 1
}
