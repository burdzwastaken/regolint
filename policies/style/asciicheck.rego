package regolint.rules.style.asciicheck

metadata := {
	"id": "asciicheck",
	"severity": "warning",
	"description": "Checks for non-ASCII identifiers",
}

non_ascii(value) if regex.match(`[^\x00-\x7F]`, value)

identifier contains {"name": input.package.name, "kind": "package", "position": {"file": input.file_path, "line": 1, "column": 1}} if {
	non_ascii(input.package.name)
}

identifier contains {"name": fn.name, "kind": "function", "position": fn.position} if {
	some fn in input.functions
	non_ascii(fn.name)
}

identifier contains {"name": param.name, "kind": "parameter", "position": fn.position} if {
	some fn in input.functions
	some param in fn.parameters
	param.name != ""
	non_ascii(param.name)
}

identifier contains {"name": ret.name, "kind": "return value", "position": fn.position} if {
	some fn in input.functions
	some ret in fn.returns
	ret.name != ""
	non_ascii(ret.name)
}

identifier contains {"name": typ.name, "kind": "type", "position": typ.position} if {
	some typ in input.types
	non_ascii(typ.name)
}

identifier contains {"name": field.name, "kind": "field", "position": field.position} if {
	some typ in input.types
	some field in typ.fields
	not field.is_embedded
	non_ascii(field.name)
}

identifier contains {"name": method.name, "kind": "method", "position": typ.position} if {
	some typ in input.types
	some method in typ.methods
	non_ascii(method.name)
}

identifier contains {"name": v.name, "kind": "variable", "position": v.position} if {
	some v in input.variables
	non_ascii(v.name)
}

identifier contains {"name": c.name, "kind": "constant", "position": c.position} if {
	some c in input.constants
	non_ascii(c.name)
}

deny contains violation if {
	some ident in identifier

	violation := {
		"message": sprintf("%s identifier '%s' contains non-ASCII characters", [ident.kind, ident.name]),
		"position": ident.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
