package regolint.rules.style.interfacebloat

metadata := {
	"id": "interfacebloat",
	"severity": "warning",
	"description": "Checks for interfaces with too many methods",
	"max_methods": 10,
}

deny contains violation if {
	some typ in input.types
	typ.kind == "interface"
	method_count := count(typ.methods)
	method_count > metadata.max_methods

	violation := {
		"message": sprintf("Interface '%s' has too many methods (%d > %d)", [typ.name, method_count, metadata.max_methods]),
		"position": typ.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
