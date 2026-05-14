package regolint.rules.style.predeclared

metadata := {
	"id": "predeclared",
	"severity": "warning",
	"description": "Checks for declarations that shadow predeclared identifiers",
}

predeclared := {
	"any",
	"append",
	"bool",
	"byte",
	"cap",
	"close",
	"comparable",
	"complex",
	"complex128",
	"complex64",
	"copy",
	"delete",
	"error",
	"false",
	"float32",
	"float64",
	"imag",
	"int",
	"int16",
	"int32",
	"int64",
	"int8",
	"iota",
	"len",
	"make",
	"max",
	"min",
	"new",
	"nil",
	"panic",
	"print",
	"println",
	"real",
	"recover",
	"rune",
	"string",
	"true",
	"uint",
	"uint16",
	"uint32",
	"uint64",
	"uint8",
	"uintptr",
}

shadow contains {"name": fn.name, "kind": "function", "position": fn.position} if {
	some fn in input.functions
	fn.name in predeclared
}

shadow contains {"name": param.name, "kind": "parameter", "position": fn.position} if {
	some fn in input.functions
	some param in fn.parameters
	param.name in predeclared
}

shadow contains {"name": ret.name, "kind": "return value", "position": fn.position} if {
	some fn in input.functions
	some ret in fn.returns
	ret.name in predeclared
}

shadow contains {"name": typ.name, "kind": "type", "position": typ.position} if {
	some typ in input.types
	typ.name in predeclared
}

shadow contains {"name": method.name, "kind": "interface method", "position": typ.position} if {
	some typ in input.types
	some method in typ.methods
	method.name in predeclared
}

shadow contains {"name": v.name, "kind": "variable", "position": v.position} if {
	some v in input.variables
	v.name in predeclared
}

shadow contains {"name": c.name, "kind": "constant", "position": c.position} if {
	some c in input.constants
	c.name in predeclared
}

deny contains violation if {
	some ident in shadow

	violation := {
		"message": sprintf("%s '%s' shadows a predeclared identifier", [ident.kind, ident.name]),
		"position": ident.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
