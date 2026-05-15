package regolint.rules.style.constructorinterfaces_test

import data.regolint.rules.style.constructorinterfaces

test_inactive_without_configuration if {
	violations := constructorinterfaces.deny with input as {"functions": [{
		"name": "NewService",
		"is_exported": true,
		"parameters": [{"name": "db", "type": "*sql.DB"}],
		"position": {"line": 10},
	}]}
	count(violations) == 0
}

test_detects_forbidden_constructor_dependency if {
	violations := constructorinterfaces.deny with input as {
		"rule_options": {"constructorinterfaces": {"dependency_rules": [{
			"parameter_names": ["db"],
			"forbidden_types": ["*sql.DB"],
		}]}},
		"functions": [{
			"name": "NewService",
			"is_exported": true,
			"parameters": [{"name": "db", "type": "*sql.DB"}],
			"position": {"line": 10},
		}],
	}
	count(violations) == 1
	violations[_].rule == "constructorinterfaces"
}

test_allows_approved_interface_type if {
	violations := constructorinterfaces.deny with input as {
		"rule_options": {"constructorinterfaces": {"dependency_rules": [{
			"parameter_names": ["repo"],
			"allowed_interfaces": ["UserRepository"],
			"forbidden_type_patterns": [".*Repository$"],
		}]}},
		"functions": [{
			"name": "NewService",
			"is_exported": true,
			"parameters": [{"name": "repo", "type": "UserRepository"}],
			"position": {"line": 10},
		}],
	}
	count(violations) == 0
}

test_ignores_unexported_constructor_by_default if {
	violations := constructorinterfaces.deny with input as {
		"rule_options": {"constructorinterfaces": {"dependency_rules": [{"forbidden_types": ["*sql.DB"]}]}},
		"functions": [{
			"name": "newService",
			"is_exported": false,
			"parameters": [{"name": "db", "type": "*sql.DB"}],
			"position": {"line": 10},
		}],
	}
	count(violations) == 0
}

test_checks_unexported_when_configured if {
	violations := constructorinterfaces.deny with input as {
		"rule_options": {"constructorinterfaces": {
			"require_exported": false,
			"constructor_prefixes": ["new"],
			"dependency_rules": [{"forbidden_types": ["*sql.DB"]}],
		}},
		"functions": [{
			"name": "newService",
			"is_exported": false,
			"parameters": [{"name": "db", "type": "*sql.DB"}],
			"position": {"line": 10},
		}],
	}
	count(violations) == 1
}

test_ignores_non_constructor_prefix if {
	violations := constructorinterfaces.deny with input as {
		"rule_options": {"constructorinterfaces": {"dependency_rules": [{"forbidden_types": ["*sql.DB"]}]}},
		"functions": [{
			"name": "OpenService",
			"is_exported": true,
			"parameters": [{"name": "db", "type": "*sql.DB"}],
			"position": {"line": 10},
		}],
	}
	count(violations) == 0
}

test_uses_custom_constructor_prefix if {
	violations := constructorinterfaces.deny with input as {
		"rule_options": {"constructorinterfaces": {
			"constructor_prefixes": ["Open"],
			"dependency_rules": [{"forbidden_types": ["*sql.DB"]}],
		}},
		"functions": [{
			"name": "OpenService",
			"is_exported": true,
			"parameters": [{"name": "db", "type": "*sql.DB"}],
			"position": {"line": 10},
		}],
	}
	count(violations) == 1
}

test_allows_configured_function if {
	violations := constructorinterfaces.deny with input as {
		"rule_options": {"constructorinterfaces": {
			"allowed_functions": ["NewService"],
			"dependency_rules": [{"forbidden_types": ["*sql.DB"]}],
		}},
		"functions": [{
			"name": "NewService",
			"is_exported": true,
			"parameters": [{"name": "db", "type": "*sql.DB"}],
			"position": {"line": 10},
		}],
	}
	count(violations) == 0
}

test_matches_type_identity if {
	violations := constructorinterfaces.deny with input as {
		"rule_options": {"constructorinterfaces": {"dependency_rules": [{"forbidden_types": ["database/sql.DB"]}]}},
		"functions": [{
			"name": "NewService",
			"is_exported": true,
			"parameters": [{"name": "db", "type": "DB", "type_identity": "database/sql.DB"}],
			"position": {"line": 10},
		}],
	}
	count(violations) == 1
}

test_supports_custom_message if {
	violations := constructorinterfaces.deny with input as {
		"rule_options": {"constructorinterfaces": {"dependency_rules": [{
			"forbidden_types": ["*sql.DB"],
			"message": "constructors should accept storage interfaces",
		}]}},
		"functions": [{
			"name": "NewService",
			"is_exported": true,
			"parameters": [{"name": "db", "type": "*sql.DB"}],
			"position": {"line": 10},
		}],
	}
	violations[_].message == "constructors should accept storage interfaces"
}

test_detects_legacy_configuration if {
	violations := constructorinterfaces.deny with input as {
		"constructor_interface_rules": [{"forbidden_types": ["*sql.DB"]}],
		"functions": [{
			"name": "NewService",
			"is_exported": true,
			"parameters": [{"name": "db", "type": "*sql.DB"}],
			"position": {"line": 10},
		}],
	}
	count(violations) == 1
}
