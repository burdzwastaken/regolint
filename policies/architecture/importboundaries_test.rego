package regolint.rules.architecture.importboundaries_test

import data.regolint.rules.architecture.importboundaries

test_inactive_without_configuration if {
	violations := importboundaries.deny with input as {
		"package": {"path": "github.com/example/app/internal/infrastructure/sql"},
		"imports": [{"path": "github.com/example/app/internal/application/users", "position": {"line": 5}}],
	}
	count(violations) == 0
}

test_detects_forbidden_import_boundary if {
	violations := importboundaries.deny with input as {
		"rule_options": {"importboundaries": {"rules": [{
			"from": ".*/internal/infrastructure(/.*)?$",
			"forbidden": [".*/internal/application(/.*)?$"],
		}]}},
		"package": {"path": "github.com/example/app/internal/infrastructure/sql"},
		"imports": [{"path": "github.com/example/app/internal/application/users", "position": {"line": 5}}],
	}
	count(violations) == 1
	violations[_].rule == "importboundaries"
}

test_allows_import_when_current_package_does_not_match_from if {
	violations := importboundaries.deny with input as {
		"rule_options": {"importboundaries": {"rules": [{
			"from": ".*/internal/infrastructure(/.*)?$",
			"forbidden": [".*/internal/application(/.*)?$"],
		}]}},
		"package": {"path": "github.com/example/app/internal/domain"},
		"imports": [{"path": "github.com/example/app/internal/application/users", "position": {"line": 5}}],
	}
	count(violations) == 0
}

test_allows_import_when_import_does_not_match_forbidden if {
	violations := importboundaries.deny with input as {
		"rule_options": {"importboundaries": {"rules": [{
			"from": ".*/internal/infrastructure(/.*)?$",
			"forbidden": [".*/internal/application(/.*)?$"],
		}]}},
		"package": {"path": "github.com/example/app/internal/infrastructure/sql"},
		"imports": [{"path": "github.com/example/app/internal/domain/users", "position": {"line": 5}}],
	}
	count(violations) == 0
}

test_detects_multiple_matching_imports if {
	violations := importboundaries.deny with input as {
		"rule_options": {"importboundaries": {"rules": [{
			"from": ".*/internal/infrastructure(/.*)?$",
			"forbidden": [".*/internal/application(/.*)?$"],
		}]}},
		"package": {"path": "github.com/example/app/internal/infrastructure/sql"},
		"imports": [
			{"path": "github.com/example/app/internal/application/users", "position": {"line": 5}},
			{"path": "github.com/example/app/internal/domain/users", "position": {"line": 6}},
			{"path": "github.com/example/app/internal/application/billing", "position": {"line": 7}},
		],
	}
	count(violations) == 2
}

test_supports_custom_violation_message if {
	violations := importboundaries.deny with input as {
		"rule_options": {"importboundaries": {"rules": [{
			"from": ".*/internal/infrastructure(/.*)?$",
			"forbidden": [".*/internal/application(/.*)?$"],
			"message": "infrastructure must not import application",
		}]}},
		"package": {"path": "github.com/example/app/internal/infrastructure/sql"},
		"imports": [{"path": "github.com/example/app/internal/application/users", "position": {"line": 5}}],
	}
	violations[_].message == "infrastructure must not import application"
}

test_detects_legacy_configuration if {
	violations := importboundaries.deny with input as {
		"import_boundary_rules": [{
			"from": ".*/internal/infrastructure(/.*)?$",
			"forbidden": [".*/internal/application(/.*)?$"],
		}],
		"package": {"path": "github.com/example/app/internal/infrastructure/sql"},
		"imports": [{"path": "github.com/example/app/internal/application/users", "position": {"line": 5}}],
	}
	count(violations) == 1
}
