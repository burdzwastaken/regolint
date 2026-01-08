package regolint.rules.security.credentials_test

import data.regolint.rules.security.credentials

test_detects_password_constant if {
	violations := credentials.deny with input as {
		"constants": [{"name": "dbPassword", "position": {"line": 10}}],
		"variables": [],
	}
	count(violations) == 1
}

test_detects_api_key_constant if {
	violations := credentials.deny with input as {
		"constants": [{"name": "API_KEY", "position": {"line": 10}}],
		"variables": [],
	}
	count(violations) == 1
}

test_detects_secret_constant if {
	violations := credentials.deny with input as {
		"constants": [{"name": "clientSecret", "position": {"line": 10}}],
		"variables": [],
	}
	count(violations) == 1
}

test_allows_safe_constants if {
	violations := credentials.deny with input as {
		"constants": [
			{"name": "MaxRetries", "position": {"line": 10}},
			{"name": "DefaultTimeout", "position": {"line": 11}},
		],
		"variables": [],
	}
	count(violations) == 0
}

test_detects_package_level_password_var if {
	violations := credentials.deny with input as {
		"constants": [],
		"variables": [{"name": "password", "in_function": "", "position": {"line": 10}}],
	}
	count(violations) == 1
}

test_ignores_local_password_var if {
	violations := credentials.deny with input as {
		"constants": [],
		"variables": [{"name": "password", "in_function": "hashPassword", "position": {"line": 10}}],
	}
	count(violations) == 0
}
