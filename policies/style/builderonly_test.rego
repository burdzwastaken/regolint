package regolint.rules.style.builderonly_test

import data.regolint.rules.style.builderonly

test_inactive_without_configuration if {
	violations := builderonly.deny with input as {"composite_literals": [{"type": "ClientConfig", "position": {"line": 10}}]}
	count(violations) == 0
}

test_detects_direct_configured_literal if {
	violations := builderonly.deny with input as {
		"rule_options": {"builderonly": {"types": ["ClientConfig"]}},
		"composite_literals": [{"type": "ClientConfig", "position": {"line": 10}}],
	}
	count(violations) == 1
	violations[_].rule == "builderonly"
}

test_allows_configured_builder_function if {
	violations := builderonly.deny with input as {
		"rule_options": {"builderonly": {
			"types": ["ClientConfig"],
			"allowed_functions": ["NewClientConfigBuilder"],
		}},
		"composite_literals": [{
			"type": "ClientConfig",
			"in_function": "NewClientConfigBuilder",
			"position": {"line": 10},
		}],
	}
	count(violations) == 0
}

test_allows_test_files if {
	violations := builderonly.deny with input as {
		"file_path": "client_config_test.go",
		"rule_options": {"builderonly": {"types": ["ClientConfig"]}},
		"composite_literals": [{"type": "ClientConfig", "position": {"line": 10}}],
	}
	count(violations) == 0
}

test_detects_type_identity_match if {
	violations := builderonly.deny with input as {
		"rule_options": {"builderonly": {"types": ["example.com/project.ClientConfig"]}},
		"composite_literals": [{
			"type": "ClientConfig",
			"type_identity": "example.com/project.ClientConfig",
			"position": {"line": 10},
		}],
	}
	count(violations) == 1
}
