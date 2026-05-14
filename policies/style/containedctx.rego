package regolint.rules.style.containedctx

metadata := {
	"id": "containedctx",
	"severity": "warning",
	"description": "Checks for context.Context fields inside structs",
}

is_context_type(type_name) if type_name == "context.Context"

is_context_type(type_name) if type_name == "*context.Context"

deny contains violation if {
	some typ in input.types
	typ.kind == "struct"
	some field in typ.fields
	is_context_type(field.type)

	violation := {
		"message": sprintf("Struct '%s' contains context.Context field '%s'", [typ.name, field.name]),
		"position": field.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
