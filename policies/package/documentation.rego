package regolint.rules.package.documentation

metadata := {
	"id": "doccheck",
	"severity": "warning",
	"description": "Checks that exported types have documentation",
}

deny contains violation if {
	some t in input.all_types
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
	some fn in input.all_functions
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
