package regolint.rules.style.inamedparam

metadata := {
	"id": "inamedparam",
	"severity": "warning",
	"description": "Checks that interface method parameters are named",
}

unnamed(param) if not param.name

unnamed(param) if param.name == ""

deny contains violation if {
	some typ in input.types
	typ.kind == "interface"
	some method in typ.methods
	some param in method.parameters
	unnamed(param)

	violation := {
		"message": sprintf("Interface method '%s.%s' has unnamed parameter of type '%s'", [typ.name, method.name, param.type]),
		"position": typ.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
