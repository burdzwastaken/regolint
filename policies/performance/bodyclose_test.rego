package regolint.rules.performance.bodyclose_test

import data.regolint.rules.performance.bodyclose

test_detects_unclosed_response_body if {
	violations := bodyclose.deny with input as {
		"resource_acquires": [{"kind": "http_response", "target": "resp", "source": "http.Get", "in_function": "fetch", "position": {"line": 10, "column": 10}}],
		"resource_closes": [],
	}
	count(violations) == 1
	violations[_].rule == "bodyclose"
}

test_allows_closed_response_body if {
	violations := bodyclose.deny with input as {
		"resource_acquires": [{"kind": "http_response", "target": "resp", "source": "http.Get", "in_function": "fetch", "position": {"line": 10, "column": 10}}],
		"resource_closes": [{"target": "resp.Body", "is_defer": true, "in_function": "fetch", "position": {"line": 11, "column": 2}}],
	}
	count(violations) == 0
}

test_ignores_close_before_acquire if {
	violations := bodyclose.deny with input as {
		"resource_acquires": [{"kind": "http_response", "target": "resp", "source": "http.Get", "in_function": "fetch", "position": {"line": 10, "column": 10}}],
		"resource_closes": [{"target": "resp.Body", "is_defer": true, "in_function": "fetch", "position": {"line": 9, "column": 2}}],
	}
	count(violations) == 1
}

test_ignores_other_resource_kinds if {
	violations := bodyclose.deny with input as {
		"resource_acquires": [{"kind": "sql_rows", "target": "rows", "source": "db.Query", "in_function": "fetch", "position": {"line": 10, "column": 10}}],
		"resource_closes": [],
	}
	count(violations) == 0
}

test_ignores_close_after_reacquire if {
	violations := bodyclose.deny with input as {
		"resource_acquires": [
			{"kind": "http_response", "target": "resp", "source": "http.Get", "in_function": "fetch", "position": {"line": 10, "column": 10}},
			{"kind": "http_response", "target": "resp", "source": "http.Get", "in_function": "fetch", "position": {"line": 15, "column": 10}},
		],
		"resource_closes": [{"target": "resp.Body", "is_defer": true, "in_function": "fetch", "position": {"line": 20, "column": 2}}],
	}
	count(violations) == 1
}
