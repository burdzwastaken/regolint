package regolint.rules.architecture.layers_test

import data.regolint.rules.architecture.layers

test_domain_cannot_import_application if {
	violations := layers.deny with input as {
		"module_path": "github.com/example/app",
		"package": {"path": "github.com/example/app/domain"},
		"imports": [{"path": "github.com/example/app/application", "position": {"line": 5}}],
	}
	count(violations) == 1
}

test_domain_cannot_import_infrastructure if {
	violations := layers.deny with input as {
		"module_path": "github.com/example/app",
		"package": {"path": "github.com/example/app/domain"},
		"imports": [{"path": "github.com/example/app/infrastructure", "position": {"line": 5}}],
	}
	count(violations) == 1
}

test_application_can_import_domain if {
	violations := layers.deny with input as {
		"module_path": "github.com/example/app",
		"package": {"path": "github.com/example/app/application"},
		"imports": [{"path": "github.com/example/app/domain", "position": {"line": 5}}],
	}
	count(violations) == 0
}

test_application_cannot_import_infrastructure if {
	violations := layers.deny with input as {
		"module_path": "github.com/example/app",
		"package": {"path": "github.com/example/app/application"},
		"imports": [{"path": "github.com/example/app/infrastructure", "position": {"line": 5}}],
	}
	count(violations) == 1
}

test_infrastructure_can_import_domain if {
	violations := layers.deny with input as {
		"module_path": "github.com/example/app",
		"package": {"path": "github.com/example/app/infrastructure"},
		"imports": [{"path": "github.com/example/app/domain", "position": {"line": 5}}],
	}
	count(violations) == 0
}

test_infrastructure_can_import_application if {
	violations := layers.deny with input as {
		"module_path": "github.com/example/app",
		"package": {"path": "github.com/example/app/infrastructure"},
		"imports": [{"path": "github.com/example/app/application", "position": {"line": 5}}],
	}
	count(violations) == 0
}

test_allows_external_imports if {
	violations := layers.deny with input as {
		"module_path": "github.com/example/app",
		"package": {"path": "github.com/example/app/domain"},
		"imports": [{"path": "fmt", "position": {"line": 5}}],
	}
	count(violations) == 0
}

test_allows_same_layer_imports if {
	violations := layers.deny with input as {
		"module_path": "github.com/example/app",
		"package": {"path": "github.com/example/app/domain"},
		"imports": [{"path": "github.com/example/app/domain/user", "position": {"line": 5}}],
	}
	count(violations) == 0
}
