package regolint.rules.package.documentation

metadata := {
	"id": "PKG001",
	"severity": "warning",
	"description": "Checks that exported types have documentation",
}

# Support both file context (types) and package context (all_types)
types_to_check := input.all_types if input.all_types
types_to_check := input.types if not input.all_types

functions_to_check := input.all_functions if input.all_functions
functions_to_check := input.functions if not input.all_functions

deny contains violation if {
	some t in types_to_check
	t.is_exported
	t.doc == ""

	violation := {
		"message": sprintf("Exported type '%s' should have documentation", [t.name]),
		"position": t.position,
		"rule": metadata.id,
		"severity": metadata.severity,
		"fix": {"description": sprintf("Add a doc comment above type %s", [t.name])},
	}
}

deny contains violation if {
	some fn in functions_to_check
	fn.is_exported
	not fn.is_test
	count(fn.comments) == 0

	violation := {
		"message": sprintf("Exported function '%s' should have documentation", [fn.name]),
		"position": fn.position,
		"rule": metadata.id,
		"severity": metadata.severity,
		"fix": {"description": sprintf("Add a doc comment above function %s", [fn.name])},
	}
}
