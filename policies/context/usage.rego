package regolint.rules.context.usage

metadata := {
	"id": "CTX001",
	"severity": "warning",
	"description": "Checks for proper context.Context usage",
}

deny contains violation if {
	some fn in input.functions
	fn.is_exported
	count(fn.parameters) > 0

	first_param := fn.parameters[0]
	first_param.type == "context.Context"
	first_param.name != "ctx"

	violation := {
		"message": sprintf("Function '%s' should name context parameter 'ctx', not '%s'", [fn.name, first_param.name]),
		"position": fn.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}

deny contains violation if {
	some fn in input.functions
	fn.is_exported
	count(fn.parameters) > 1

	has_context := [p | some p in fn.parameters; p.type == "context.Context"]
	count(has_context) > 0

	fn.parameters[0].type != "context.Context"

	violation := {
		"message": sprintf("Function '%s' should have context.Context as first parameter", [fn.name]),
		"position": fn.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
