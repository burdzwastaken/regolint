package regolint.rules.imports.importas_test

import data.regolint.rules.imports.importas

test_detects_missing_expected_alias if {
	violations := importas.deny with input as {"imports": [{"path": "k8s.io/api/core/v1", "position": {"line": 4}}]}
	count(violations) == 1
	violations[_].rule == "importas"
}

test_allows_expected_alias if {
	violations := importas.deny with input as {"imports": [{"path": "k8s.io/api/core/v1", "alias": "corev1", "position": {"line": 4}}]}
	count(violations) == 0
}

test_allows_unconfigured_import if {
	violations := importas.deny with input as {"imports": [{"path": "fmt", "position": {"line": 4}}]}
	count(violations) == 0
}

test_allows_natural_package_name_without_explicit_alias if {
	violations := importas.deny with input as {"imports": [{"path": "sigs.k8s.io/controller-runtime/pkg/client", "position": {"line": 4}}]}
	count(violations) == 0
}

test_uses_input_alias_configuration if {
	violations := importas.deny with input as {"import_aliases": {"example.com/pkg/v2": "pkgv2"}, "imports": [{"path": "example.com/pkg/v2", "alias": "wrong", "position": {"line": 4}}]}
	count(violations) == 1
}
