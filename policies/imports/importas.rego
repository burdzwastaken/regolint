package regolint.rules.imports.importas

metadata := {
	"id": "importas",
	"severity": "warning",
	"description": "Checks import aliases against expected names",
}

expected_aliases := {
	"k8s.io/api/core/v1": "corev1",
	"k8s.io/api/apps/v1": "appsv1",
	"k8s.io/api/batch/v1": "batchv1",
	"k8s.io/apimachinery/pkg/apis/meta/v1": "metav1",
	"k8s.io/apimachinery/pkg/api/errors": "apierrors",
}

configured_aliases := object.get(input, "import_aliases", {})

alias_for(path) := alias if alias := configured_aliases[path]

alias_for(path) := alias if {
	not configured_aliases[path]
	alias := expected_aliases[path]
}

deny contains violation if {
	some imp in input.imports
	expected := alias_for(imp.path)
	actual := object.get(imp, "alias", "")
	actual != expected

	violation := {
		"message": sprintf("Import '%s' should use alias '%s'", [imp.path, expected]),
		"position": imp.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
