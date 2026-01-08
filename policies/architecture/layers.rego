package regolint.rules.architecture.layers

metadata := {
	"id": "ARCH001",
	"severity": "error",
	"description": "Enforces clean architecture layer dependencies",
}

layer_rules := {
	"domain": [],
	"application": ["domain"],
	"infrastructure": ["domain", "application"],
	"interfaces": ["domain", "application"],
}

default get_layer(_) := "unknown"

get_layer(pkg) := layer if {
	parts := split(pkg, "/")
	layer := parts[count(parts) - 1]
	layer in object.keys(layer_rules)
}

deny contains violation if {
	current_layer := get_layer(input.package.path)
	current_layer != "unknown"

	some imp in input.imports
	startswith(imp.path, input.module_path)

	imported_layer := get_layer(imp.path)
	imported_layer != "unknown"

	allowed := layer_rules[current_layer]
	not imported_layer in allowed
	current_layer != imported_layer

	violation := {
		"message": sprintf("Layer violation: '%s' cannot import from '%s'", [current_layer, imported_layer]),
		"position": imp.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
