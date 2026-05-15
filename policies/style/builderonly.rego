package regolint.rules.style.builderonly

metadata := {
	"id": "builderonly",
	"severity": "warning",
	"description": "Checks configured types are constructed through builders",
}

builderonly_options := object.get(object.get(input, "rule_options", {}), "builderonly", {})

builder_only_types := object.get(builderonly_options, "types", object.get(input, "builder_only_types", []))

builder_only_allowed_functions := object.get(builderonly_options, "allowed_functions", object.get(input, "builder_only_allowed_functions", []))

configured_type(lit) if lit.type in builder_only_types

configured_type(lit) if object.get(lit, "type_identity", "") in builder_only_types

allowed_context(_) if endswith(object.get(input, "file_path", ""), "_test.go")

allowed_context(lit) if lit.in_function in builder_only_allowed_functions

deny contains violation if {
	some lit in input.composite_literals
	configured_type(lit)
	not allowed_context(lit)

	violation := {
		"message": sprintf("use a builder instead of direct %s literal", [lit.type]),
		"position": lit.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
